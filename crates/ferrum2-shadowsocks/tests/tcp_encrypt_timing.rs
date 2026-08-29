mod common;
#[path = "common/tcp_encrypt_measurement.rs"]
mod tcp_encrypt_measurement;

use std::time::{Duration, Instant};

use tcp_encrypt_measurement::{PAYLOAD_LENGTHS, measure_steady_frames};

const WARMUP_FRAMES: usize = 64;
const MEASURED_FRAMES: usize = 2_048;
const SAMPLES: usize = 5;

/// Reproducible release-only micro workload. It reports timing without a
/// machine-sensitive threshold:
///
/// `cargo test --release -p ferrum2-shadowsocks --test tcp_encrypt_timing
/// --locked -- --ignored --exact --nocapture --test-threads=1`
#[test]
#[ignore = "release-only performance diagnostic"]
fn release_timing_for_steady_tcp_frame_encrypt() {
    require_release_build();

    for payload_len in PAYLOAD_LENGTHS {
        let mut samples = Vec::with_capacity(SAMPLES);
        for sample in 1..=SAMPLES {
            let measurement = measure_steady_frames(
                payload_len,
                WARMUP_FRAMES,
                MEASURED_FRAMES,
                Instant::now,
                |started| started.elapsed(),
            );
            let elapsed = measurement.observation;
            print_sample(payload_len, sample, elapsed, measurement.checksum);
            samples.push(elapsed);
        }
        samples.sort_unstable();
        print_summary(payload_len, samples[SAMPLES / 2]);
    }
}

#[cfg(debug_assertions)]
fn require_release_build() {
    panic!("this diagnostic must be run with cargo test --release");
}

#[cfg(not(debug_assertions))]
fn require_release_build() {}

fn print_sample(payload_len: usize, sample: usize, elapsed: Duration, checksum: u64) {
    println!(
        "tcp_encrypt_timing payload_bytes={payload_len} sample={sample} frames={MEASURED_FRAMES} \
         elapsed_ns={} ns_per_frame={:.1} payload_mib_per_second={:.3} checksum={checksum}",
        elapsed.as_nanos(),
        elapsed.as_secs_f64() * 1_000_000_000.0 / MEASURED_FRAMES as f64,
        payload_throughput_mib(payload_len, elapsed),
    );
}

fn print_summary(payload_len: usize, median: Duration) {
    println!(
        "tcp_encrypt_timing_summary payload_bytes={payload_len} samples={SAMPLES} \
         frames_per_sample={MEASURED_FRAMES} median_elapsed_ns={} median_ns_per_frame={:.1} \
         median_payload_mib_per_second={:.3}",
        median.as_nanos(),
        median.as_secs_f64() * 1_000_000_000.0 / MEASURED_FRAMES as f64,
        payload_throughput_mib(payload_len, median),
    );
}

fn payload_throughput_mib(payload_len: usize, elapsed: Duration) -> f64 {
    let payload_bytes = (payload_len * MEASURED_FRAMES) as f64;
    payload_bytes / (1024.0 * 1024.0) / elapsed.as_secs_f64()
}
