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

#[test]
fn reader_bookends_witness_initial_and_final_generations_without_counting_them() {
    let _guard = allocator_test_lock();
    let fixture = Arc::new(build_snapshot_fixture().expect("snapshot fixture"));
    let successor = prebuild_successors(&fixture, 1)
        .expect("successor")
        .pop()
        .expect("one successor");
    let initial_generation = fixture.registry.snapshot().generation();
    let final_generation = successor.generation();
    let handshake = ReaderHandshake {
        start: Arc::new(Barrier::new(2)),
        finish: Arc::new(Barrier::new(2)),
        release: Arc::new(Barrier::new(2)),
        active_readers: Arc::new(AtomicUsize::new(0)),
        writer_active: Arc::new(AtomicBool::new(true)),
    };
    let witness = Arc::new(ReaderWitness::new());
    let scratch = fixture.program.evaluation_scratch().expect("scratch");
    let reader = spawn_reader(
        Arc::clone(&fixture),
        handshake.clone(),
        Arc::clone(&witness),
        0,
        scratch,
    );

    handshake.start.wait();
    fixture
        .registry
        .publish(successor)
        .expect("publish successor");
    handshake.finish.wait();
    handshake.release.wait();

    let result = join_reader(reader).expect("reader");
    assert_eq!(result.minimum_generation, initial_generation);
    assert_eq!(result.maximum_generation, final_generation);
    assert_eq!(witness.operations.load(Ordering::Acquire), 0);
}
