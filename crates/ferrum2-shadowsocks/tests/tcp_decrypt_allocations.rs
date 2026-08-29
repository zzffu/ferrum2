mod common;
#[path = "common/tcp_decrypt_measurement.rs"]
mod tcp_decrypt_measurement;

use std::alloc::System;

use stats_alloc::{Region, Stats, StatsAlloc};

use tcp_decrypt_measurement::{PAYLOAD_LENGTHS, measure_steady_frames};

#[global_allocator]
static GLOBAL_ALLOCATOR: StatsAlloc<System> = StatsAlloc::system();

const WARMUP_FRAMES: usize = 16;
const MEASURED_FRAMES: usize = 128;

/// Baseline/candidate command:
///
/// `cargo test -p ferrum2-shadowsocks --features tokio --test
/// tcp_decrypt_allocations --locked -- --nocapture --test-threads=1`
///
/// Set `FERRUM2_REQUIRE_ZERO_DECRYPT_ALLOCATIONS=1` only for the phase-1
/// candidate acceptance run. Keeping the default run diagnostic lets exactly
/// the same harness record the pre-optimization baseline.
#[tokio::test(flavor = "current_thread")]
async fn reports_steady_tcp_frame_decrypt_allocations() {
    let require_zero = std::env::var_os("FERRUM2_REQUIRE_ZERO_DECRYPT_ALLOCATIONS").is_some();

    for payload_len in PAYLOAD_LENGTHS {
        let measurement = measure_steady_frames(
            payload_len,
            WARMUP_FRAMES,
            MEASURED_FRAMES,
            || Region::new(&GLOBAL_ALLOCATOR),
            |region| region.change(),
        )
        .await;
        let stats = measurement.observation;
        print_stats(payload_len, stats, measurement.checksum);

        assert_eq!(
            stats.reallocations, 0,
            "steady decrypt reallocated for {payload_len}-byte frames"
        );
        if require_zero {
            assert_eq!(
                stats.allocations, 0,
                "phase-1 steady decrypt allocated for {payload_len}-byte frames"
            );
            assert_eq!(
                stats.bytes_allocated, 0,
                "phase-1 steady decrypt allocated bytes for {payload_len}-byte frames"
            );
        }
    }
}

fn print_stats(payload_len: usize, stats: Stats, checksum: u64) {
    println!(
        "tcp_decrypt_alloc payload_bytes={payload_len} frames={MEASURED_FRAMES} \
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
