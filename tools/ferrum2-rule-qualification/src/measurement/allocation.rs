use std::alloc::System;
use std::hint::black_box;
use std::time::Instant;

use ferrum2_rule::CompiledMatchSet;
use stats_alloc::{Region, StatsAlloc};

use crate::cli::{QualificationError, Result};
use crate::match_set::benchmark::{MatchProbe, probe_matches};
use crate::measurement::statistics::nearest_rank;
use crate::report::{AllocationEvidence, AllocationSample, BenchResult, BuildEvidence};

#[global_allocator]
static GLOBAL_ALLOCATOR: StatsAlloc<System> = StatsAlloc::system();

pub(crate) const ALLOCATION_SAMPLES: usize = 5;

pub(crate) fn allocation_region() -> Region<'static, System> {
    Region::new(&GLOBAL_ALLOCATOR)
}

#[cfg(test)]
static ALLOCATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn allocator_test_lock() -> std::sync::MutexGuard<'static, ()> {
    ALLOCATION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn measure_allocations(
    operation: &mut impl FnMut() -> u64,
    mut checksum: u64,
) -> AllocationEvidence {
    let mut allocation_samples = Vec::with_capacity(ALLOCATION_SAMPLES);
    let mut total_allocations = 0_u128;
    let mut total_reallocations = 0_u128;
    let mut total_bytes_allocated = 0_u128;
    let mut total_bytes_deallocated = 0_u128;
    for _ in 0..ALLOCATION_SAMPLES {
        let allocation_region = allocation_region();
        checksum = checksum.rotate_left(1) ^ black_box(operation());
        let allocation_change = allocation_region.change();
        total_allocations += allocation_change.allocations as u128;
        total_reallocations += allocation_change.reallocations as u128;
        total_bytes_allocated += allocation_change.bytes_allocated as u128;
        total_bytes_deallocated += allocation_change.bytes_deallocated as u128;
        allocation_samples.push(AllocationSample {
            iterations: 1,
            allocations: usize_to_u64(allocation_change.allocations),
            deallocations: usize_to_u64(allocation_change.deallocations),
            reallocations: usize_to_u64(allocation_change.reallocations),
            bytes_allocated: usize_to_u64(allocation_change.bytes_allocated),
            bytes_deallocated: usize_to_u64(allocation_change.bytes_deallocated),
        });
    }
    let total_operations = ALLOCATION_SAMPLES as f64;
    AllocationEvidence {
        samples: allocation_samples,
        allocations_per_op: total_allocations as f64 / total_operations,
        reallocations_per_op: total_reallocations as f64 / total_operations,
        bytes_allocated_per_op: total_bytes_allocated as f64 / total_operations,
        bytes_deallocated_per_op: total_bytes_deallocated as f64 / total_operations,
        allocation_free: total_allocations == 0 && total_reallocations == 0,
        checksum,
    }
}

pub(crate) fn measure_pair_allocations(
    set: &CompiledMatchSet,
    probe: &MatchProbe,
    mut checksum: u64,
) -> AllocationEvidence {
    let mut allocation_samples = Vec::with_capacity(ALLOCATION_SAMPLES);
    let mut total_allocations = 0_u128;
    let mut total_reallocations = 0_u128;
    let mut total_bytes_allocated = 0_u128;
    let mut total_bytes_deallocated = 0_u128;
    for _ in 0..ALLOCATION_SAMPLES {
        let allocation_region = allocation_region();
        checksum = checksum.rotate_left(1) ^ black_box(u64::from(probe_matches(set, probe)));
        let allocation_change = allocation_region.change();
        total_allocations += allocation_change.allocations as u128;
        total_reallocations += allocation_change.reallocations as u128;
        total_bytes_allocated += allocation_change.bytes_allocated as u128;
        total_bytes_deallocated += allocation_change.bytes_deallocated as u128;
        allocation_samples.push(AllocationSample {
            iterations: 1,
            allocations: usize_to_u64(allocation_change.allocations),
            deallocations: usize_to_u64(allocation_change.deallocations),
            reallocations: usize_to_u64(allocation_change.reallocations),
            bytes_allocated: usize_to_u64(allocation_change.bytes_allocated),
            bytes_deallocated: usize_to_u64(allocation_change.bytes_deallocated),
        });
    }
    let total_operations = ALLOCATION_SAMPLES as f64;
    AllocationEvidence {
        samples: allocation_samples,
        allocations_per_op: total_allocations as f64 / total_operations,
        reallocations_per_op: total_reallocations as f64 / total_operations,
        bytes_allocated_per_op: total_bytes_allocated as f64 / total_operations,
        bytes_deallocated_per_op: total_bytes_deallocated as f64 / total_operations,
        allocation_free: total_allocations == 0 && total_reallocations == 0,
        checksum,
    }
}

pub(crate) fn bench_result(
    timings: Vec<f64>,
    actual_iterations_per_sample: Vec<u64>,
    sample_batch_nanoseconds: Vec<u64>,
    timing_pair_id: Option<String>,
    paired_sample_order: Option<Vec<&'static str>>,
    allocation: AllocationEvidence,
) -> BenchResult {
    let p50 = nearest_rank(&timings, 50);
    let p99 = nearest_rank(&timings, 99);
    BenchResult {
        samples: timings,
        actual_iterations_per_sample,
        sample_batch_nanoseconds,
        timing_pair_id,
        paired_sample_order,
        p50,
        p99,
        checksum: allocation.checksum,
        allocation_samples: allocation.samples,
        allocations_per_op: allocation.allocations_per_op,
        reallocations_per_op: allocation.reallocations_per_op,
        bytes_allocated_per_op: allocation.bytes_allocated_per_op,
        bytes_deallocated_per_op: allocation.bytes_deallocated_per_op,
        allocation_free: allocation.allocation_free,
    }
}

pub(crate) fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub(crate) fn finish_build(started: Instant, region: &Region<'_, System>) -> Result<BuildEvidence> {
    let change = region.change();
    let allocated = usize_to_u64(change.bytes_allocated);
    let deallocated = usize_to_u64(change.bytes_deallocated);
    let net_retained_bytes = allocated.checked_sub(deallocated).ok_or_else(|| {
        QualificationError::new("instrumented build region released pre-existing allocations")
    })?;
    Ok(BuildEvidence {
        nanoseconds: started.elapsed().as_nanos(),
        allocations: usize_to_u64(change.allocations),
        reallocations: usize_to_u64(change.reallocations),
        net_retained_bytes,
    })
}
