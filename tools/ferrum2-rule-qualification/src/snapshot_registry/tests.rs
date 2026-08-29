use super::*;

#[test]
fn lifecycle_evidence_recomputes_bounded_multi_generation_retention() {
    let _guard = allocator_test_lock();
    let evidence = verify_snapshot_lifecycle().expect("snapshot lifecycle");
    assert_eq!(evidence.reader_threads, SNAPSHOT_READER_THREADS);
    assert_eq!(evidence.publish_count, SNAPSHOT_LIFECYCLE_PUBLISH_COUNT);
    assert_eq!(evidence.publish_records.len(), evidence.publish_count);
    assert_eq!(
        evidence.peak_live_old_snapshots,
        evidence
            .publish_records
            .iter()
            .map(|record| record.live_old_snapshots)
            .max()
            .expect("publish record")
    );
    assert_eq!(
        evidence.peak_retained_bytes,
        evidence
            .publish_records
            .iter()
            .map(|record| record.retained_bytes)
            .max()
            .expect("publish record")
    );
    assert!(evidence.all_old_snapshots_released);
    assert!(evidence.release_within_deadline);
    assert!(evidence.release_ns <= evidence.release_deadline_ns);
    assert!(evidence.generation_action_consistent);
    assert!(evidence.publish_monotonic);
    assert!(evidence.watch_no_missed_publication);
}

#[test]
fn successors_are_prebuilt_monotonic_and_action_consistent() {
    let _guard = allocator_test_lock();
    let fixture = build_snapshot_fixture().expect("snapshot fixture");
    let successors = prebuild_successors(&fixture, 3).expect("successors");
    assert_eq!(
        successors
            .iter()
            .map(RuleEngineSnapshot::generation)
            .collect::<Vec<_>>(),
        vec![2, 3, 4]
    );
    publish_all(&fixture.registry, successors, false).expect("publish successors");
    let mut scratch = fixture.program.evaluation_scratch().expect("scratch");
    assert_eq!(
        evaluate_once(&fixture, &mut scratch).expect("evaluate"),
        (4, 0)
    );
}
