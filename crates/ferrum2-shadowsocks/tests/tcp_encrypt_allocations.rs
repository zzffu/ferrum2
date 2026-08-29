mod common;
#[path = "common/tcp_encrypt_measurement.rs"]
mod tcp_encrypt_measurement;

use std::alloc::System;

use stats_alloc::{Region, Stats, StatsAlloc};

use tcp_encrypt_measurement::{PAYLOAD_LENGTHS, measure_steady_frames};

#[global_allocator]
static GLOBAL_ALLOCATOR: StatsAlloc<System> = StatsAlloc::system();

const WARMUP_FRAMES: usize = 16;
const MEASURED_FRAMES: usize = 128;

/// Baseline/candidate command:
///
/// `cargo test -p ferrum2-shadowsocks --test tcp_encrypt_allocations --locked
/// -- --nocapture --test-threads=1`
#[test]
fn steady_tcp_frame_encrypt_allocates_nothing() {
    for payload_len in PAYLOAD_LENGTHS {
        let measurement = measure_steady_frames(
            payload_len,
            WARMUP_FRAMES,
            MEASURED_FRAMES,
            || Region::new(&GLOBAL_ALLOCATOR),
            |region| region.change(),
        );
        let stats = measurement.observation;
        print_stats(payload_len, stats, measurement.checksum);

        assert_eq!(
            stats.allocations, 0,
            "steady encrypt allocated for {payload_len}-byte frames"
        );
        assert_eq!(
            stats.reallocations, 0,
            "steady encrypt reallocated for {payload_len}-byte frames"
        );
        assert_eq!(
            stats.bytes_allocated, 0,
            "steady encrypt allocated bytes for {payload_len}-byte frames"
        );
        assert_eq!(
            stats.bytes_reallocated, 0,
            "steady encrypt reallocated bytes for {payload_len}-byte frames"
        );
    }
}

fn print_stats(payload_len: usize, stats: Stats, checksum: u64) {
    println!(
        "tcp_encrypt_alloc payload_bytes={payload_len} frames={MEASURED_FRAMES} \
         allocations={} reallocations={} bytes_allocated={} bytes_reallocated={} \
         allocations_per_frame={:.3} bytes_allocated_per_frame={:.3} checksum={checksum}",
        stats.allocations,
        stats.reallocations,
        stats.bytes_allocated,
        stats.bytes_reallocated,
        stats.allocations as f64 / MEASURED_FRAMES as f64,
        stats.bytes_allocated as f64 / MEASURED_FRAMES as f64,
    );
}
