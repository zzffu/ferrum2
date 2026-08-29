use std::future::Future;
use std::hint::black_box;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;
use ferrum2_rule::{
    CompiledMatchSet, GenerationChange, MatchSetBuilder, OrderedRouteProgram, OrderedRouteRule,
    RegistryPublishError, RouteMatchField, RouteMatcher, RouteMetadata, RouteProgramAction,
    RouteRuleAction, RuleEngineRegistry, RuleEngineSnapshot, RuleEngineSnapshotBuilder,
    RuleEvaluationScratch, RuleSetId,
};

use crate::cli::{QualificationError, Result};
use crate::measurement::allocation::{
    ALLOCATION_SAMPLES, allocation_region, finish_build, measure_allocations,
};
use crate::measurement::statistics::measurement;
use crate::measurement::timing::MIN_SAMPLE_WINDOW_NANOSECONDS;
use crate::report::{BenchResult, BuildEvidence, Measurement, SnapshotLifecycleEvidence};

#[cfg(test)]
use crate::measurement::allocation::allocator_test_lock;

pub(crate) const SNAPSHOT_READER_THREADS: usize = 4;
const INITIAL_READS_PER_READER: usize = 256;
const INITIAL_PUBLISHES_PER_SAMPLE: usize = 256;
const MAX_READS_PER_READER: usize = 65_536;
const MAX_PUBLISHES_PER_SAMPLE: usize = 16_384;

#[derive(Clone)]
struct SnapshotFixture {
    program: Arc<OrderedRouteProgram<(), u8>>,
    registry: Arc<RuleEngineRegistry>,
    target: TargetAddr,
    first: RuleSetId,
    second: RuleSetId,
    matching: Arc<CompiledMatchSet>,
    missing: Arc<CompiledMatchSet>,
    build: BuildEvidence,
}

struct ReaderBatch {
    elapsed_nanoseconds: u64,
    checksum: u64,
    minimum_generation: u64,
    maximum_generation: u64,
}

#[derive(Clone)]
struct ReaderHandshake {
    start: Arc<Barrier>,
    finish: Arc<Barrier>,
    release: Arc<Barrier>,
    active_readers: Arc<AtomicUsize>,
    writer_active: Arc<AtomicBool>,
}

#[repr(align(64))]
struct ReaderWitness {
    operations: AtomicU64,
    maximum_generation: AtomicU64,
}

impl ReaderWitness {
    const fn new() -> Self {
        Self {
            operations: AtomicU64::new(0),
            maximum_generation: AtomicU64::new(0),
        }
    }

    fn record_checkpoint(&self, operations: usize, maximum_generation: u64) {
        self.maximum_generation
            .store(maximum_generation, Ordering::Release);
        self.operations
            .store(usize_to_u64(operations), Ordering::Release);
    }
}

pub(crate) fn run_snapshot_registry(
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<SnapshotLifecycleEvidence> {
    let lifecycle = verify_snapshot_lifecycle()?;

    let read_fixture = Arc::new(build_snapshot_fixture()?);
    let read_build = read_fixture.build;
    let initial_reads = bounded_initial_count(
        base_iterations,
        INITIAL_READS_PER_READER,
        MAX_READS_PER_READER,
    );
    let read_result =
        benchmark_read_under_publish(Arc::clone(&read_fixture), samples, initial_reads)?;
    measurements.push(measurement(
        "snapshot_registry/registry_read/read_under_publish".to_owned(),
        "snapshot_registry",
        "registry_read",
        "read_under_publish",
        SNAPSHOT_READER_THREADS,
        None,
        None,
        usize_to_u64(initial_reads.saturating_mul(SNAPSHOT_READER_THREADS)),
        read_build,
        Some(2),
        read_result,
    ));

    let publish_fixture = Arc::new(build_snapshot_fixture()?);
    let publish_build = publish_fixture.build;
    let initial_publishes = bounded_initial_count(
        base_iterations / 8,
        INITIAL_PUBLISHES_PER_SAMPLE,
        MAX_PUBLISHES_PER_SAMPLE,
    );
    let publish_result =
        benchmark_publish_under_readers(Arc::clone(&publish_fixture), samples, initial_publishes)?;
    measurements.push(measurement(
        "snapshot_registry/registry_publish/publish_under_readers".to_owned(),
        "snapshot_registry",
        "registry_publish",
        "publish_under_readers",
        SNAPSHOT_READER_THREADS,
        None,
        None,
        usize_to_u64(initial_publishes),
        publish_build,
        Some(2),
        publish_result,
    ));
    Ok(lifecycle)
}

fn build_snapshot_fixture() -> Result<SnapshotFixture> {
    let region = allocation_region();
    let started = Instant::now();
    let matching = Arc::new(exact_match_set("fixed.bench.invalid")?);
    let missing = Arc::new(exact_match_set("miss.bench.invalid")?);
    let mut snapshot = RuleEngineSnapshotBuilder::new(1);
    let first_match = snapshot
        .add_shared_match_set(Arc::clone(&missing))
        .map_err(|error| QualificationError::new(format!("snapshot fixture failed: {error}")))?;
    let second_match = snapshot
        .add_shared_match_set(Arc::clone(&matching))
        .map_err(|error| QualificationError::new(format!("snapshot fixture failed: {error}")))?;
    let first = snapshot
        .add_rule_set("snapshot-first", first_match)
        .map_err(|error| QualificationError::new(format!("snapshot fixture failed: {error}")))?;
    let second = snapshot
        .add_rule_set("snapshot-second", second_match)
        .map_err(|error| QualificationError::new(format!("snapshot fixture failed: {error}")))?;
    let program = OrderedRouteProgram::try_new(
        vec![
            OrderedRouteRule::new(
                RouteMatcher::<()>::try_new(vec![RouteMatchField::RuleSet(vec![first])]).map_err(
                    |error| QualificationError::new(format!("snapshot matcher failed: {error}")),
                )?,
                RouteRuleAction::Terminal(0),
            ),
            OrderedRouteRule::new(
                RouteMatcher::<()>::try_new(vec![RouteMatchField::RuleSet(vec![second])]).map_err(
                    |error| QualificationError::new(format!("snapshot matcher failed: {error}")),
                )?,
                RouteRuleAction::Terminal(1),
            ),
        ],
        2,
    )
    .map_err(|error| QualificationError::new(format!("snapshot program failed: {error}")))?;
    let initial = snapshot
        .build()
        .map_err(|error| QualificationError::new(format!("snapshot fixture failed: {error}")))?;
    let target = TargetAddr::domain("fixed.bench.invalid", 443)
        .map_err(|_| QualificationError::new("snapshot target is invalid"))?;
    let registry = Arc::new(RuleEngineRegistry::new(initial));
    let program = Arc::new(program);
    let build = finish_build(started, &region)?;
    Ok(SnapshotFixture {
        program,
        registry,
        target,
        first,
        second,
        matching,
        missing,
        build,
    })
}

fn exact_match_set(value: &str) -> Result<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    builder
        .add_exact_domain(value)
        .map_err(|error| QualificationError::new(format!("snapshot MatchSet failed: {error}")))?;
    builder
        .build()
        .map_err(|error| QualificationError::new(format!("snapshot MatchSet failed: {error}")))
}

fn prebuild_successors(fixture: &SnapshotFixture, count: usize) -> Result<Vec<RuleEngineSnapshot>> {
    let current = fixture.registry.snapshot();
    let mut successors = Vec::new();
    successors
        .try_reserve_exact(count)
        .map_err(|_| QualificationError::new("snapshot successor reservation failed"))?;
    for offset in 1..=count {
        let generation = current
            .generation()
            .checked_add(usize_to_u64(offset))
            .ok_or_else(|| QualificationError::new("snapshot generation overflowed"))?;
        let mut builder = current
            .builder_for_generation(generation)
            .map_err(|error| {
                QualificationError::new(format!("snapshot successor failed: {error}"))
            })?;
        let (first, second) = if generation % 2 == 0 {
            (&fixture.matching, &fixture.missing)
        } else {
            (&fixture.missing, &fixture.matching)
        };
        builder
            .replace_shared_rule_set(fixture.first, Arc::clone(first))
            .and_then(|()| builder.replace_shared_rule_set(fixture.second, Arc::clone(second)))
            .map_err(|error| {
                QualificationError::new(format!("snapshot successor failed: {error}"))
            })?;
        successors.push(builder.build().map_err(|error| {
            QualificationError::new(format!("snapshot successor failed: {error}"))
        })?);
    }
    Ok(successors)
}

fn evaluate_once(
    fixture: &SnapshotFixture,
    scratch: &mut RuleEvaluationScratch,
) -> Result<(u64, u8)> {
    let mut evaluation = fixture.program.evaluate_with_registry_and_scratch(
        0,
        Network::Tcp,
        &fixture.target,
        &fixture.registry,
        scratch,
    );
    let generation = evaluation
        .snapshot_generation()
        .ok_or_else(|| QualificationError::new("snapshot evaluation captured no generation"))?;
    let action = match evaluation.next(RouteMetadata::new(None, None)) {
        Some(RouteProgramAction::Terminal(action)) | Some(RouteProgramAction::Final(action)) => {
            *action
        }
        Some(RouteProgramAction::Continue(_)) | None => {
            return Err(QualificationError::new(
                "snapshot evaluation returned an incomplete action",
            ));
        }
    };
    if u64::from(action) != generation % 2 {
        return Err(QualificationError::new(
            "snapshot generation and action are inconsistent",
        ));
    }
    Ok((generation, action))
}

fn spawn_reader(
    fixture: Arc<SnapshotFixture>,
    handshake: ReaderHandshake,
    witness: Arc<ReaderWitness>,
    operations: usize,
    mut scratch: RuleEvaluationScratch,
) -> thread::JoinHandle<Result<ReaderBatch>> {
    thread::spawn(move || {
        handshake.active_readers.fetch_add(1, Ordering::AcqRel);
        handshake.start.wait();
        let started = Instant::now();
        let outcome = (|| {
            let checkpoint_interval = operations.div_ceil(8).max(1);
            let mut checksum = 0_u64;
            let mut minimum_generation = u64::MAX;
            let mut maximum_generation = 0_u64;
            for index in 0..operations {
                let (generation, action) = evaluate_once(&fixture, &mut scratch)?;
                minimum_generation = minimum_generation.min(generation);
                maximum_generation = maximum_generation.max(generation);
                checksum = checksum.rotate_left(5) ^ generation ^ u64::from(action);
                let completed = index + 1;
                if completed <= 8
                    || completed.is_multiple_of(checkpoint_interval)
                    || completed == operations
                {
                    witness.record_checkpoint(completed, maximum_generation);
                }
            }
            Ok(ReaderBatch {
                elapsed_nanoseconds: elapsed_nanoseconds(started),
                checksum: black_box(checksum),
                minimum_generation,
                maximum_generation,
            })
        })();
        handshake.finish.wait();
        let writer_remained_active = handshake.writer_active.load(Ordering::Acquire);
        handshake.release.wait();
        handshake.active_readers.fetch_sub(1, Ordering::AcqRel);
        if !writer_remained_active {
            return failure("snapshot reader/writer liveness failed");
        }
        outcome
    })
}

fn read_under_publish_sample(
    fixture: Arc<SnapshotFixture>,
    reads_per_reader: usize,
) -> Result<ReaderBatch> {
    let publish_count = reads_per_reader.div_ceil(4).clamp(16, 1_024);
    let successors = prebuild_successors(&fixture, publish_count)?;
    let final_generation = successors
        .last()
        .map(RuleEngineSnapshot::generation)
        .ok_or_else(|| QualificationError::new("snapshot successors are empty"))?;
    let handshake = ReaderHandshake {
        start: Arc::new(Barrier::new(SNAPSHOT_READER_THREADS + 1)),
        finish: Arc::new(Barrier::new(SNAPSHOT_READER_THREADS + 1)),
        release: Arc::new(Barrier::new(SNAPSHOT_READER_THREADS + 1)),
        active_readers: Arc::new(AtomicUsize::new(0)),
        writer_active: Arc::new(AtomicBool::new(false)),
    };
    let witnesses = reader_witnesses();
    let mut readers = Vec::with_capacity(SNAPSHOT_READER_THREADS);
    for (scratch, witness) in reader_scratches(&fixture)?.into_iter().zip(&witnesses) {
        readers.push(spawn_reader(
            Arc::clone(&fixture),
            handshake.clone(),
            Arc::clone(witness),
            reads_per_reader,
            scratch,
        ));
    }
    let writer_registry = Arc::clone(&fixture.registry);
    let writer_handshake = handshake;
    let writer_witnesses = witnesses.clone();
    let writer = thread::spawn(move || {
        writer_handshake
            .writer_active
            .store(true, Ordering::Release);
        writer_handshake.start.wait();
        let entered =
            writer_handshake.active_readers.load(Ordering::Acquire) == SNAPSHOT_READER_THREADS;
        let operations_before = witness_operations(&writer_witnesses);
        let outcome = publish_all(&writer_registry, successors, true);
        let operations_after = witness_operations(&writer_witnesses);
        writer_handshake.finish.wait();
        let readers_remained_active =
            writer_handshake.active_readers.load(Ordering::Acquire) == SNAPSHOT_READER_THREADS;
        writer_handshake.release.wait();
        writer_handshake
            .writer_active
            .store(false, Ordering::Release);
        if !entered || !readers_remained_active || operations_after <= operations_before {
            return failure("snapshot read-under-publish did not overlap");
        }
        outcome
    });

    let mut elapsed = 0_u64;
    let writer_outcome = join_writer(writer);
    let mut reader_results = Vec::with_capacity(SNAPSHOT_READER_THREADS);
    let mut reader_failure = None;
    for reader in readers {
        match join_reader(reader) {
            Ok(result) => reader_results.push(result),
            Err(error) if reader_failure.is_none() => reader_failure = Some(error),
            Err(_) => {}
        }
    }
    let mut checksum = writer_outcome?;
    if let Some(error) = reader_failure {
        return Err(error);
    }
    let mut minimum_generation = u64::MAX;
    let mut maximum_generation = 0_u64;
    for result in reader_results {
        elapsed = elapsed.max(result.elapsed_nanoseconds);
        checksum ^= result.checksum.rotate_left(7);
        minimum_generation = minimum_generation.min(result.minimum_generation);
        maximum_generation = maximum_generation.max(result.maximum_generation);
    }
    if minimum_generation >= maximum_generation || maximum_generation != final_generation {
        return failure("snapshot reader publication witness failed");
    }
    Ok(ReaderBatch {
        elapsed_nanoseconds: elapsed.max(1),
        checksum,
        minimum_generation,
        maximum_generation,
    })
}

fn spawn_background_reader(
    fixture: Arc<SnapshotFixture>,
    ready: Arc<Barrier>,
    stop: Arc<AtomicBool>,
    active_readers: Arc<AtomicUsize>,
    writer_active: Arc<AtomicBool>,
    witness: Arc<ReaderWitness>,
    mut scratch: RuleEvaluationScratch,
) -> thread::JoinHandle<Result<ReaderBatch>> {
    thread::spawn(move || {
        active_readers.fetch_add(1, Ordering::AcqRel);
        let started = Instant::now();
        let mut checksum = 0_u64;
        let mut operations = 0_usize;
        let mut minimum_generation = u64::MAX;
        let mut maximum_generation = 0_u64;
        let mut reader_error = None;
        match evaluate_once(&fixture, &mut scratch) {
            Ok((generation, action)) => {
                operations = 1;
                minimum_generation = generation;
                maximum_generation = generation;
                checksum = generation ^ u64::from(action);
                witness.record_checkpoint(operations, maximum_generation);
            }
            Err(error) => reader_error = Some(error),
        }
        ready.wait();
        while reader_error.is_none() && !stop.load(Ordering::Acquire) {
            match evaluate_once(&fixture, &mut scratch) {
                Ok((generation, action)) => {
                    operations = operations.saturating_add(1);
                    minimum_generation = minimum_generation.min(generation);
                    maximum_generation = maximum_generation.max(generation);
                    checksum = checksum.rotate_left(5) ^ generation ^ u64::from(action);
                    if operations <= 8 || operations.is_multiple_of(64) {
                        witness.record_checkpoint(operations, maximum_generation);
                    }
                }
                Err(error) => reader_error = Some(error),
            }
        }
        if operations > 0 {
            witness.record_checkpoint(operations, maximum_generation);
        }
        let writer_remained_active = writer_active.load(Ordering::Acquire);
        active_readers.fetch_sub(1, Ordering::AcqRel);
        if let Some(error) = reader_error {
            return Err(error);
        }
        if !writer_remained_active {
            return failure("snapshot background reader liveness failed");
        }
        Ok(ReaderBatch {
            elapsed_nanoseconds: elapsed_nanoseconds(started),
            checksum: black_box(checksum),
            minimum_generation,
            maximum_generation,
        })
    })
}

fn publish_under_readers_sample(
    fixture: Arc<SnapshotFixture>,
    publish_count: usize,
) -> Result<ReaderBatch> {
    let successors = prebuild_successors(&fixture, publish_count)?;
    let final_generation = successors
        .last()
        .map(RuleEngineSnapshot::generation)
        .ok_or_else(|| QualificationError::new("snapshot successors are empty"))?;
    let ready = Arc::new(Barrier::new(SNAPSHOT_READER_THREADS + 1));
    let stop = Arc::new(AtomicBool::new(false));
    let active_readers = Arc::new(AtomicUsize::new(0));
    let writer_active = Arc::new(AtomicBool::new(true));
    let witnesses = reader_witnesses();
    let mut readers = Vec::with_capacity(SNAPSHOT_READER_THREADS);
    for (scratch, witness) in reader_scratches(&fixture)?.into_iter().zip(&witnesses) {
        readers.push(spawn_background_reader(
            Arc::clone(&fixture),
            Arc::clone(&ready),
            Arc::clone(&stop),
            Arc::clone(&active_readers),
            Arc::clone(&writer_active),
            Arc::clone(witness),
            scratch,
        ));
    }
    ready.wait();
    let entered = active_readers.load(Ordering::Acquire) == SNAPSHOT_READER_THREADS;
    let operations_before = witness_operations(&witnesses);
    let started = Instant::now();
    let publish_outcome = publish_all(&fixture.registry, successors, false);
    let elapsed = elapsed_nanoseconds(started).max(1);
    let operations_during_publish = witness_operations(&witnesses);
    let observed_final = if publish_outcome.is_ok() {
        wait_for_reader_generation(&witnesses, &active_readers, final_generation)
    } else {
        Ok(())
    };
    let readers_remained_active = active_readers.load(Ordering::Acquire) == SNAPSHOT_READER_THREADS;
    stop.store(true, Ordering::Release);
    let mut reader_results = Vec::with_capacity(SNAPSHOT_READER_THREADS);
    let mut reader_failure = None;
    for reader in readers {
        match join_reader(reader) {
            Ok(result) => reader_results.push(result),
            Err(error) if reader_failure.is_none() => reader_failure = Some(error),
            Err(_) => {}
        }
    }
    writer_active.store(false, Ordering::Release);
    let mut checksum = publish_outcome?;
    observed_final?;
    if let Some(error) = reader_failure {
        return Err(error);
    }
    if !entered || !readers_remained_active || operations_during_publish <= operations_before {
        return failure("snapshot publish-under-readers did not overlap");
    }
    let mut minimum_generation = u64::MAX;
    let mut maximum_generation = 0_u64;
    for result in reader_results {
        checksum ^= result.checksum.rotate_left(11);
        minimum_generation = minimum_generation.min(result.minimum_generation);
        maximum_generation = maximum_generation.max(result.maximum_generation);
    }
    if minimum_generation >= maximum_generation || maximum_generation != final_generation {
        return failure("snapshot background publication witness failed");
    }
    Ok(ReaderBatch {
        elapsed_nanoseconds: elapsed,
        checksum,
        minimum_generation,
        maximum_generation,
    })
}

fn benchmark_read_under_publish(
    fixture: Arc<SnapshotFixture>,
    samples: usize,
    initial_reads: usize,
) -> Result<BenchResult> {
    let mut reads = initial_reads;
    let mut timings = Vec::with_capacity(samples);
    let mut actual_iterations = Vec::with_capacity(samples);
    let mut batch_nanoseconds = Vec::with_capacity(samples);
    let mut checksum = 0_u64;
    while timings.len() < samples {
        let result = read_under_publish_sample(Arc::clone(&fixture), reads)?;
        let grown = grow_count(
            reads,
            result.elapsed_nanoseconds,
            MAX_READS_PER_READER,
            "snapshot read-under-publish",
        )?;
        if grown != reads {
            reads = grown;
            continue;
        }
        let operations = reads.saturating_mul(SNAPSHOT_READER_THREADS);
        timings.push(result.elapsed_nanoseconds as f64 / operations as f64);
        actual_iterations.push(usize_to_u64(operations));
        batch_nanoseconds.push(result.elapsed_nanoseconds);
        checksum ^= result.checksum.rotate_left(13);
    }
    let allocation = measure_read_allocations(&fixture, checksum)?;
    Ok(crate::measurement::allocation::bench_result(
        timings,
        actual_iterations,
        batch_nanoseconds,
        None,
        None,
        allocation,
    ))
}

fn benchmark_publish_under_readers(
    fixture: Arc<SnapshotFixture>,
    samples: usize,
    initial_publishes: usize,
) -> Result<BenchResult> {
    let mut publishes = initial_publishes;
    let mut timings = Vec::with_capacity(samples);
    let mut actual_iterations = Vec::with_capacity(samples);
    let mut batch_nanoseconds = Vec::with_capacity(samples);
    let mut checksum = 0_u64;
    while timings.len() < samples {
        let result = publish_under_readers_sample(Arc::clone(&fixture), publishes)?;
        let grown = grow_count(
            publishes,
            result.elapsed_nanoseconds,
            MAX_PUBLISHES_PER_SAMPLE,
            "snapshot publish-under-readers",
        )?;
        if grown != publishes {
            publishes = grown;
            continue;
        }
        timings.push(result.elapsed_nanoseconds as f64 / publishes as f64);
        actual_iterations.push(usize_to_u64(publishes));
        batch_nanoseconds.push(result.elapsed_nanoseconds);
        checksum ^= result.checksum.rotate_left(17);
    }
    let allocation = measure_publish_allocations(&fixture, checksum)?;
    Ok(crate::measurement::allocation::bench_result(
        timings,
        actual_iterations,
        batch_nanoseconds,
        None,
        None,
        allocation,
    ))
}

fn measure_read_allocations(
    fixture: &SnapshotFixture,
    checksum: u64,
) -> Result<crate::report::AllocationEvidence> {
    let mut scratch = fixture.program.evaluation_scratch().map_err(|error| {
        QualificationError::new(format!("snapshot allocation scratch failed: {error}"))
    })?;
    let mut failure = None;
    let allocation = measure_allocations(
        &mut || match evaluate_once(fixture, &mut scratch) {
            Ok((generation, action)) => generation ^ u64::from(action),
            Err(error) => {
                failure = Some(error);
                0
            }
        },
        checksum,
    );
    match failure {
        Some(error) => Err(error),
        None => Ok(allocation),
    }
}

fn measure_publish_allocations(
    fixture: &SnapshotFixture,
    checksum: u64,
) -> Result<crate::report::AllocationEvidence> {
    let mut successors = prebuild_successors(fixture, ALLOCATION_SAMPLES)?.into_iter();
    let mut returned = Vec::with_capacity(ALLOCATION_SAMPLES);
    let mut failure = None;
    let allocation = measure_allocations(
        &mut || {
            let Some(next) = successors.next() else {
                failure = Some(QualificationError::new(
                    "snapshot allocation successors were exhausted",
                ));
                return 0;
            };
            let generation = next.generation();
            match fixture.registry.publish(next) {
                Ok(old) => {
                    returned.push(old);
                    generation
                }
                Err(error) => {
                    failure = Some(QualificationError::new(format!(
                        "snapshot allocation publish failed: {error}"
                    )));
                    0
                }
            }
        },
        checksum,
    );
    match failure {
        Some(error) => Err(error),
        None => Ok(allocation),
    }
}

fn publish_all(
    registry: &RuleEngineRegistry,
    successors: Vec<RuleEngineSnapshot>,
    yield_between: bool,
) -> Result<u64> {
    let mut checksum = 0_u64;
    for next in successors {
        let generation = next.generation();
        let old = registry.publish(next).map_err(|error| {
            QualificationError::new(format!("snapshot publication failed: {error}"))
        })?;
        if old.generation() >= generation {
            return Err(QualificationError::new(
                "snapshot publication was not monotonic",
            ));
        }
        checksum = checksum.rotate_left(3) ^ generation ^ old.generation();
        if yield_between {
            thread::yield_now();
        }
    }
    Ok(black_box(checksum))
}

fn reader_witnesses() -> Vec<Arc<ReaderWitness>> {
    (0..SNAPSHOT_READER_THREADS)
        .map(|_| Arc::new(ReaderWitness::new()))
        .collect()
}

fn witness_operations(witnesses: &[Arc<ReaderWitness>]) -> u64 {
    witnesses.iter().fold(0_u64, |total, witness| {
        total.saturating_add(witness.operations.load(Ordering::Acquire))
    })
}

fn witness_maximum_generation(witnesses: &[Arc<ReaderWitness>]) -> u64 {
    witnesses
        .iter()
        .map(|witness| witness.maximum_generation.load(Ordering::Acquire))
        .max()
        .unwrap_or(0)
}

fn wait_for_reader_generation(
    witnesses: &[Arc<ReaderWitness>],
    active_readers: &AtomicUsize,
    expected: u64,
) -> Result<()> {
    let started = Instant::now();
    while witness_maximum_generation(witnesses) < expected {
        if active_readers.load(Ordering::Acquire) != SNAPSHOT_READER_THREADS {
            return failure("snapshot reader stopped before generation witness");
        }
        if started.elapsed() >= Duration::from_secs(5) {
            return failure("snapshot generation witness timed out");
        }
        thread::yield_now();
    }
    Ok(())
}

fn reader_scratches(fixture: &SnapshotFixture) -> Result<Vec<RuleEvaluationScratch>> {
    (0..SNAPSHOT_READER_THREADS)
        .map(|_| {
            fixture.program.evaluation_scratch().map_err(|error| {
                QualificationError::new(format!("snapshot reader scratch failed: {error}"))
            })
        })
        .collect()
}

fn verify_snapshot_lifecycle() -> Result<SnapshotLifecycleEvidence> {
    let fixture = Arc::new(build_snapshot_fixture()?);
    let initial = fixture.registry.snapshot();
    let initial_generation = initial.generation();
    let weak = Arc::downgrade(&initial);
    let mut successors = prebuild_successors(&fixture, 1)?;
    let successor = successors
        .pop()
        .ok_or_else(|| QualificationError::new("snapshot successor is missing"))?;
    let published_generation = successor.generation();
    let stale = initial
        .builder_for_generation(published_generation)
        .and_then(RuleEngineSnapshotBuilder::build)
        .map_err(|error| QualificationError::new(format!("snapshot lifecycle failed: {error}")))?;

    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
    let reader_fixture = Arc::clone(&fixture);
    let (captured_sender, captured_receiver) = std::sync::mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let outcome = (|| {
            let mut scratch = reader_fixture
                .program
                .evaluation_scratch()
                .map_err(|error| {
                    QualificationError::new(format!("snapshot lifecycle scratch failed: {error}"))
                })?;
            let mut evaluation = reader_fixture.program.evaluate_with_registry_and_scratch(
                0,
                Network::Tcp,
                &reader_fixture.target,
                &reader_fixture.registry,
                &mut scratch,
            );
            let generation = evaluation.snapshot_generation().ok_or_else(|| {
                QualificationError::new("snapshot lifecycle captured no generation")
            })?;
            let action = match evaluation.next(RouteMetadata::new(None, None)) {
                Some(RouteProgramAction::Terminal(action))
                | Some(RouteProgramAction::Final(action)) => *action,
                Some(RouteProgramAction::Continue(_)) | None => {
                    return Err(QualificationError::new(
                        "snapshot lifecycle returned an incomplete action",
                    ));
                }
            };
            captured_sender
                .send(Ok((generation, action)))
                .map_err(|_| QualificationError::new("snapshot lifecycle channel closed"))?;
            release_receiver.recv().map_err(|_| {
                QualificationError::new("snapshot lifecycle release channel closed")
            })?;
            drop(evaluation);
            Ok(())
        })();
        if let Err(error) = outcome {
            let _ = captured_sender.send(Err(error));
            let _ = release_receiver.recv();
        }
    });

    let captured = captured_receiver
        .recv()
        .map_err(|_| QualificationError::new("snapshot lifecycle reader stopped"));
    let outcome = (|| {
        let (reader_generation, reader_action) = captured??;
        let returned_old = fixture.registry.publish(successor).map_err(|error| {
            QualificationError::new(format!("snapshot lifecycle publish failed: {error}"))
        })?;
        let returned_old_generation = returned_old.generation();
        let returned_old_matches_initial = Arc::ptr_eq(&initial, &returned_old);
        let publish_monotonic = matches!(
            fixture.registry.publish(stale),
            Err(RegistryPublishError::StaleGeneration)
        ) && fixture.registry.generation() == published_generation;
        let mut scratch = fixture.program.evaluation_scratch().map_err(|error| {
            QualificationError::new(format!("snapshot lifecycle scratch failed: {error}"))
        })?;
        let (fresh_generation, fresh_action) = evaluate_once(&fixture, &mut scratch)?;
        let mut watch = fixture.registry.watch_generation_from(initial_generation);
        let watch_observed_generation = poll_generation(&mut watch).ok_or_else(|| {
            QualificationError::new("snapshot lifecycle watch missed publication")
        })?;
        drop(returned_old);
        drop(initial);
        let old_snapshot_alive_before_reader_release = weak.upgrade().is_some();
        Ok((
            reader_generation,
            reader_action,
            fresh_generation,
            fresh_action,
            returned_old_generation,
            returned_old_matches_initial,
            publish_monotonic,
            watch_observed_generation,
            old_snapshot_alive_before_reader_release,
        ))
    })();
    let _ = release_sender.send(());
    reader
        .join()
        .map_err(|_| QualificationError::new("snapshot lifecycle reader panicked"))?;
    let old_snapshot_released_after_reader_release = weak.upgrade().is_none();
    let (
        reader_generation,
        reader_action,
        fresh_generation,
        fresh_action,
        returned_old_generation,
        returned_old_matches_initial,
        publish_monotonic,
        watch_observed_generation,
        old_snapshot_alive_before_reader_release,
    ) = outcome?;
    let generation_action_consistent = reader_generation == initial_generation
        && u64::from(reader_action) == reader_generation % 2
        && fresh_generation == published_generation
        && u64::from(fresh_action) == fresh_generation % 2;
    let watch_no_missed_publication = watch_observed_generation == published_generation;
    if !returned_old_matches_initial
        || returned_old_generation != initial_generation
        || !old_snapshot_alive_before_reader_release
        || !old_snapshot_released_after_reader_release
        || !generation_action_consistent
        || !publish_monotonic
        || !watch_no_missed_publication
    {
        return Err(QualificationError::new(
            "snapshot lifecycle contract failed",
        ));
    }
    Ok(SnapshotLifecycleEvidence {
        reader_threads: SNAPSHOT_READER_THREADS,
        initial_generation,
        published_generation,
        reader_generation,
        reader_action,
        fresh_generation,
        fresh_action,
        returned_old_generation,
        returned_old_matches_initial,
        old_snapshot_alive_before_reader_release,
        old_snapshot_released_after_reader_release,
        generation_action_consistent,
        publish_monotonic,
        watch_observed_generation,
        watch_no_missed_publication,
    })
}

fn poll_generation(change: &mut GenerationChange) -> Option<u64> {
    match Future::poll(Pin::new(change), &mut Context::from_waker(Waker::noop())) {
        Poll::Ready(generation) => Some(generation),
        Poll::Pending => None,
    }
}

fn join_reader(handle: thread::JoinHandle<Result<ReaderBatch>>) -> Result<ReaderBatch> {
    handle
        .join()
        .map_err(|_| QualificationError::new("snapshot reader panicked"))?
}

fn join_writer(handle: thread::JoinHandle<Result<u64>>) -> Result<u64> {
    handle
        .join()
        .map_err(|_| QualificationError::new("snapshot writer panicked"))?
}

fn grow_count(current: usize, elapsed: u64, maximum: usize, label: &str) -> Result<usize> {
    if elapsed >= MIN_SAMPLE_WINDOW_NANOSECONDS {
        return Ok(current);
    }
    if current == maximum {
        return Err(QualificationError::new(format!(
            "{label} could not reach the minimum timing window"
        )));
    }
    let required = (current as u128)
        .saturating_mul(u128::from(MIN_SAMPLE_WINDOW_NANOSECONDS))
        .div_ceil(u128::from(elapsed.max(1)));
    let with_margin = required.saturating_mul(5).div_ceil(4);
    Ok(usize::try_from(with_margin)
        .unwrap_or(maximum)
        .max(current.saturating_add(1))
        .min(maximum))
}

fn bounded_initial_count(base: u64, minimum: usize, maximum: usize) -> usize {
    usize::try_from(base)
        .unwrap_or(maximum)
        .clamp(minimum, maximum)
}

fn elapsed_nanoseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn failure<T>(message: &'static str) -> Result<T> {
    Err(QualificationError::new(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_evidence_proves_reader_retention_release_and_watch_delivery() {
        let _guard = allocator_test_lock();
        let evidence = verify_snapshot_lifecycle().expect("snapshot lifecycle");
        assert_eq!(evidence.reader_threads, SNAPSHOT_READER_THREADS);
        assert!(evidence.returned_old_matches_initial);
        assert!(evidence.old_snapshot_alive_before_reader_release);
        assert!(evidence.old_snapshot_released_after_reader_release);
        assert!(evidence.generation_action_consistent);
        assert!(evidence.publish_monotonic);
        assert!(evidence.watch_no_missed_publication);
        assert_eq!(evidence.reader_generation, evidence.initial_generation);
        assert_eq!(evidence.fresh_generation, evidence.published_generation);
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
}
