use std::hint::black_box;
use std::time::{Duration, Instant};

use ferrum2_rule::CompiledMatchSet;

use crate::match_set::benchmark::{MatchProbe, probe_matches};
use crate::measurement::allocation::{bench_result, measure_allocations, measure_pair_allocations};
use crate::report::BenchResult;

pub(crate) const MAX_CALIBRATED_ITERATIONS: u64 = 1_000_000_000;
pub(crate) const MIN_SAMPLE_WINDOW: Duration = Duration::from_micros(100);
pub(crate) const MIN_SAMPLE_WINDOW_NANOSECONDS: u64 = MIN_SAMPLE_WINDOW.as_micros() as u64 * 1_000;
pub(crate) const WARMUP_BATCHES: usize = 5;
pub(crate) const PAIRED_ROUNDS_PER_SAMPLE: u64 = 32;

pub(crate) fn benchmark(
    mut operation: impl FnMut() -> u64,
    samples: usize,
    requested_iterations: u64,
) -> BenchResult {
    let mut checksum = warm_up_operation(&mut operation, requested_iterations);
    let mut iterations = calibrate_iterations(&mut operation, requested_iterations, &mut checksum);
    for _ in 0..WARMUP_BATCHES {
        let elapsed = timed_batch(&mut operation, iterations, &mut checksum);
        iterations = grow_iterations_if_needed(iterations, elapsed);
    }

    let mut timings = Vec::with_capacity(samples);
    let mut actual_iterations = Vec::with_capacity(samples);
    let mut batch_nanoseconds = Vec::with_capacity(samples);
    for _ in 0..samples {
        loop {
            let elapsed = timed_batch(&mut operation, iterations, &mut checksum);
            let grown = grow_iterations_if_needed(iterations, elapsed);
            if grown != iterations {
                iterations = grown;
                continue;
            }
            timings.push(elapsed as f64 / iterations as f64);
            actual_iterations.push(iterations);
            batch_nanoseconds.push(elapsed);
            break;
        }
    }
    let allocation = measure_allocations(&mut operation, checksum);
    black_box(allocation.checksum);
    bench_result(
        timings,
        actual_iterations,
        batch_nanoseconds,
        None,
        None,
        allocation,
    )
}

pub(crate) fn benchmark_pair(
    baseline: &CompiledMatchSet,
    candidate: &CompiledMatchSet,
    probe: &MatchProbe,
    samples: usize,
    requested_iterations: u64,
    pair_id: String,
) -> (BenchResult, BenchResult) {
    let mut baseline_checksum = warm_up_pair_operation(baseline, probe, requested_iterations);
    let mut candidate_checksum = warm_up_pair_operation(candidate, probe, requested_iterations);
    let baseline_iterations = calibrate_pair_iterations(
        baseline,
        probe,
        requested_iterations,
        &mut baseline_checksum,
    );
    let candidate_iterations = calibrate_pair_iterations(
        candidate,
        probe,
        requested_iterations,
        &mut candidate_checksum,
    );
    let mut iterations = baseline_iterations.max(candidate_iterations);
    let candidate_starts = stable_order_seed(&pair_id);
    // Both roles use one accumulator address while timed. Separate stack
    // slots can otherwise introduce a stable store-forwarding/alignment bias
    // large enough to dominate very fast CIDR probes.
    let mut pair_checksum = baseline_checksum ^ candidate_checksum;

    for warmup in 0..WARMUP_BATCHES {
        let candidate_first = (warmup % 2 == 0) == candidate_starts;
        let (baseline_elapsed, candidate_elapsed) = timed_pair(
            baseline,
            candidate,
            probe,
            iterations,
            candidate_first,
            &mut pair_checksum,
        );
        iterations = grow_iterations_if_needed(iterations, baseline_elapsed)
            .max(grow_iterations_if_needed(iterations, candidate_elapsed));
    }

    let mut baseline_timings = Vec::with_capacity(samples);
    let mut candidate_timings = Vec::with_capacity(samples);
    let mut actual_iterations = Vec::with_capacity(samples);
    let mut baseline_batch_nanoseconds = Vec::with_capacity(samples);
    let mut candidate_batch_nanoseconds = Vec::with_capacity(samples);
    let mut order = Vec::with_capacity(samples);
    for sample in 0..samples {
        let candidate_first = (sample % 2 == 0) == candidate_starts;
        loop {
            let (baseline_elapsed, candidate_elapsed) = timed_pair_sample(
                baseline,
                candidate,
                probe,
                iterations,
                candidate_first,
                &mut pair_checksum,
            );
            let grown = grow_iterations_if_needed(iterations, baseline_elapsed)
                .max(grow_iterations_if_needed(iterations, candidate_elapsed));
            if grown != iterations {
                iterations = grown;
                continue;
            }
            let sample_iterations = iterations.saturating_mul(PAIRED_ROUNDS_PER_SAMPLE);
            baseline_timings.push(baseline_elapsed as f64 / sample_iterations as f64);
            candidate_timings.push(candidate_elapsed as f64 / sample_iterations as f64);
            actual_iterations.push(sample_iterations);
            baseline_batch_nanoseconds.push(baseline_elapsed);
            candidate_batch_nanoseconds.push(candidate_elapsed);
            order.push(if candidate_first {
                "candidate_first"
            } else {
                "baseline_first"
            });
            break;
        }
    }

    baseline_checksum ^= pair_checksum.rotate_left(17);
    candidate_checksum ^= pair_checksum.rotate_right(11);
    let baseline_allocation = measure_pair_allocations(baseline, probe, baseline_checksum);
    let candidate_allocation = measure_pair_allocations(candidate, probe, candidate_checksum);
    black_box(baseline_allocation.checksum);
    black_box(candidate_allocation.checksum);
    let baseline_result = bench_result(
        baseline_timings,
        actual_iterations.clone(),
        baseline_batch_nanoseconds,
        Some(pair_id.clone()),
        Some(order.clone()),
        baseline_allocation,
    );
    let candidate_result = bench_result(
        candidate_timings,
        actual_iterations,
        candidate_batch_nanoseconds,
        Some(pair_id),
        Some(order),
        candidate_allocation,
    );
    (baseline_result, candidate_result)
}

pub(crate) fn benchmark_operation_pair(
    mut baseline: impl FnMut() -> u64,
    mut candidate: impl FnMut() -> u64,
    samples: usize,
    requested_iterations: u64,
    pair_id: String,
) -> (BenchResult, BenchResult) {
    let mut baseline_checksum = warm_up_operation(&mut baseline, requested_iterations);
    let mut candidate_checksum = warm_up_operation(&mut candidate, requested_iterations);
    let baseline_iterations =
        calibrate_iterations(&mut baseline, requested_iterations, &mut baseline_checksum);
    let candidate_iterations = calibrate_iterations(
        &mut candidate,
        requested_iterations,
        &mut candidate_checksum,
    );
    let mut iterations = baseline_iterations.max(candidate_iterations);
    let candidate_starts = stable_order_seed(&pair_id);

    for warmup in 0..WARMUP_BATCHES {
        let candidate_first = (warmup % 2 == 0) == candidate_starts;
        let (baseline_elapsed, candidate_elapsed) = timed_operation_pair(
            &mut baseline,
            &mut candidate,
            iterations,
            candidate_first,
            &mut baseline_checksum,
            &mut candidate_checksum,
        );
        iterations = grow_iterations_if_needed(iterations, baseline_elapsed)
            .max(grow_iterations_if_needed(iterations, candidate_elapsed));
    }

    let mut baseline_timings = Vec::with_capacity(samples);
    let mut candidate_timings = Vec::with_capacity(samples);
    let mut actual_iterations = Vec::with_capacity(samples);
    let mut baseline_batch_nanoseconds = Vec::with_capacity(samples);
    let mut candidate_batch_nanoseconds = Vec::with_capacity(samples);
    let mut order = Vec::with_capacity(samples);
    for sample in 0..samples {
        let candidate_first = (sample % 2 == 0) == candidate_starts;
        loop {
            let (baseline_elapsed, candidate_elapsed) = timed_operation_pair_sample(
                &mut baseline,
                &mut candidate,
                iterations,
                candidate_first,
                &mut baseline_checksum,
                &mut candidate_checksum,
            );
            let grown = grow_iterations_if_needed(iterations, baseline_elapsed)
                .max(grow_iterations_if_needed(iterations, candidate_elapsed));
            if grown != iterations {
                iterations = grown;
                continue;
            }
            let sample_iterations = iterations.saturating_mul(PAIRED_ROUNDS_PER_SAMPLE);
            baseline_timings.push(baseline_elapsed as f64 / sample_iterations as f64);
            candidate_timings.push(candidate_elapsed as f64 / sample_iterations as f64);
            actual_iterations.push(sample_iterations);
            baseline_batch_nanoseconds.push(baseline_elapsed);
            candidate_batch_nanoseconds.push(candidate_elapsed);
            order.push(if candidate_first {
                "candidate_first"
            } else {
                "baseline_first"
            });
            break;
        }
    }

    let baseline_allocation = measure_allocations(&mut baseline, baseline_checksum);
    let candidate_allocation = measure_allocations(&mut candidate, candidate_checksum);
    let baseline_result = bench_result(
        baseline_timings,
        actual_iterations.clone(),
        baseline_batch_nanoseconds,
        Some(pair_id.clone()),
        Some(order.clone()),
        baseline_allocation,
    );
    let candidate_result = bench_result(
        candidate_timings,
        actual_iterations,
        candidate_batch_nanoseconds,
        Some(pair_id),
        Some(order),
        candidate_allocation,
    );
    (baseline_result, candidate_result)
}

pub(crate) fn warm_up_operation(operation: &mut impl FnMut() -> u64, iterations: u64) -> u64 {
    let mut checksum = 0_u64;
    for _ in 0..iterations.min(32) {
        checksum = checksum.rotate_left(1) ^ black_box(operation());
    }
    checksum
}

pub(crate) fn warm_up_pair_operation(
    set: &CompiledMatchSet,
    probe: &MatchProbe,
    iterations: u64,
) -> u64 {
    let mut checksum = 0_u64;
    for _ in 0..iterations.min(32) {
        checksum = checksum.rotate_left(1) ^ black_box(u64::from(probe_matches(set, probe)));
    }
    checksum
}

pub(crate) fn calibrate_iterations(
    operation: &mut impl FnMut() -> u64,
    requested_iterations: u64,
    checksum: &mut u64,
) -> u64 {
    let mut iterations = requested_iterations.max(1);
    loop {
        let elapsed = timed_batch(operation, iterations, checksum);
        let grown = grow_iterations_if_needed(iterations, elapsed);
        if grown == iterations {
            return iterations;
        }
        iterations = grown;
    }
}

pub(crate) fn calibrate_pair_iterations(
    set: &CompiledMatchSet,
    probe: &MatchProbe,
    requested_iterations: u64,
    checksum: &mut u64,
) -> u64 {
    let mut iterations = requested_iterations.max(1);
    loop {
        let elapsed = timed_pair_role(set, probe, iterations, checksum);
        let grown = grow_iterations_if_needed(iterations, elapsed);
        if grown == iterations {
            return iterations;
        }
        iterations = grown;
    }
}

pub(crate) fn timed_batch(
    operation: &mut impl FnMut() -> u64,
    iterations: u64,
    checksum: &mut u64,
) -> u64 {
    let started = Instant::now();
    for _ in 0..iterations {
        *checksum = checksum.rotate_left(1) ^ black_box(operation());
    }
    elapsed_nanoseconds(started)
}

pub(crate) fn timed_pair(
    baseline: &CompiledMatchSet,
    candidate: &CompiledMatchSet,
    probe: &MatchProbe,
    iterations: u64,
    candidate_first: bool,
    pair_checksum: &mut u64,
) -> (u64, u64) {
    if candidate_first {
        let candidate_elapsed = timed_pair_role(candidate, probe, iterations, pair_checksum);
        let baseline_elapsed = timed_pair_role(baseline, probe, iterations, pair_checksum);
        (baseline_elapsed, candidate_elapsed)
    } else {
        let baseline_elapsed = timed_pair_role(baseline, probe, iterations, pair_checksum);
        let candidate_elapsed = timed_pair_role(candidate, probe, iterations, pair_checksum);
        (baseline_elapsed, candidate_elapsed)
    }
}

#[inline(never)]
pub(crate) fn timed_pair_role(
    set: &CompiledMatchSet,
    probe: &MatchProbe,
    iterations: u64,
    checksum: &mut u64,
) -> u64 {
    let started = Instant::now();
    for _ in 0..iterations {
        *checksum = checksum.rotate_left(1) ^ black_box(u64::from(probe_matches(set, probe)));
    }
    elapsed_nanoseconds(started)
}

pub(crate) fn timed_pair_sample(
    baseline: &CompiledMatchSet,
    candidate: &CompiledMatchSet,
    probe: &MatchProbe,
    iterations: u64,
    candidate_starts: bool,
    pair_checksum: &mut u64,
) -> (u64, u64) {
    let mut baseline_elapsed = 0_u64;
    let mut candidate_elapsed = 0_u64;
    for round in 0..PAIRED_ROUNDS_PER_SAMPLE {
        let candidate_first = (round % 2 == 0) == candidate_starts;
        let (baseline_round, candidate_round) = timed_pair(
            baseline,
            candidate,
            probe,
            iterations,
            candidate_first,
            pair_checksum,
        );
        baseline_elapsed = baseline_elapsed.saturating_add(baseline_round);
        candidate_elapsed = candidate_elapsed.saturating_add(candidate_round);
    }
    (baseline_elapsed, candidate_elapsed)
}

pub(crate) fn timed_operation_pair(
    baseline: &mut impl FnMut() -> u64,
    candidate: &mut impl FnMut() -> u64,
    iterations: u64,
    candidate_first: bool,
    baseline_checksum: &mut u64,
    candidate_checksum: &mut u64,
) -> (u64, u64) {
    if candidate_first {
        let candidate_elapsed = timed_batch(candidate, iterations, candidate_checksum);
        let baseline_elapsed = timed_batch(baseline, iterations, baseline_checksum);
        (baseline_elapsed, candidate_elapsed)
    } else {
        let baseline_elapsed = timed_batch(baseline, iterations, baseline_checksum);
        let candidate_elapsed = timed_batch(candidate, iterations, candidate_checksum);
        (baseline_elapsed, candidate_elapsed)
    }
}

pub(crate) fn timed_operation_pair_sample(
    baseline: &mut impl FnMut() -> u64,
    candidate: &mut impl FnMut() -> u64,
    iterations: u64,
    candidate_starts: bool,
    baseline_checksum: &mut u64,
    candidate_checksum: &mut u64,
) -> (u64, u64) {
    let mut baseline_elapsed = 0_u64;
    let mut candidate_elapsed = 0_u64;
    for round in 0..PAIRED_ROUNDS_PER_SAMPLE {
        let candidate_first = (round % 2 == 0) == candidate_starts;
        let (baseline_round, candidate_round) = timed_operation_pair(
            baseline,
            candidate,
            iterations,
            candidate_first,
            baseline_checksum,
            candidate_checksum,
        );
        baseline_elapsed = baseline_elapsed.saturating_add(baseline_round);
        candidate_elapsed = candidate_elapsed.saturating_add(candidate_round);
    }
    (baseline_elapsed, candidate_elapsed)
}

pub(crate) fn elapsed_nanoseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

pub(crate) fn grow_iterations_if_needed(iterations: u64, elapsed_nanoseconds: u64) -> u64 {
    if elapsed_nanoseconds >= MIN_SAMPLE_WINDOW_NANOSECONDS
        || iterations == MAX_CALIBRATED_ITERATIONS
    {
        return iterations;
    }
    let required = u128::from(iterations)
        .saturating_mul(u128::from(MIN_SAMPLE_WINDOW_NANOSECONDS))
        .div_ceil(u128::from(elapsed_nanoseconds.max(1)));
    let with_margin = required.saturating_mul(5).div_ceil(4);
    u64::try_from(with_margin)
        .unwrap_or(MAX_CALIBRATED_ITERATIONS)
        .max(iterations.saturating_add(1))
        .min(MAX_CALIBRATED_ITERATIONS)
}

pub(crate) fn stable_order_seed(pair_id: &str) -> bool {
    let hash = pair_id
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    hash & 1 != 0
}
