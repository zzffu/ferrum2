use std::hint::black_box;
use std::time::{Duration, Instant};

use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v2::tcp::TcpCipher;

const PAYLOAD_BYTES: usize = 32 * 1_024;
const NONCE: [u8; 12] = [0x3c; 12];
const WARMUP_ITERATIONS: usize = 256;
const MEASURED_ITERATIONS: usize = 4_096;
const SAMPLES: usize = 9;

const METHODS: [(CipherKind, &str); 3] = [
    (CipherKind::AEAD2022_BLAKE3_AES_128_GCM, "aes-128-gcm"),
    (CipherKind::AEAD2022_BLAKE3_AES_256_GCM, "aes-256-gcm"),
    (
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        "chacha20-poly1305",
    ),
];

struct Fixture {
    cipher: TcpCipher,
    ciphertext: Vec<u8>,
    tag: [u8; 16],
    plaintext: Vec<u8>,
}

#[derive(Clone, Copy)]
struct BatchObservation {
    elapsed: Duration,
    checksum: u64,
}

#[derive(Clone, Copy)]
struct PairObservation {
    copy_in_place: BatchObservation,
    out_of_place: BatchObservation,
}

/// Diagnostic-only comparison of the two valid TCP open primitive layouts.
///
/// Run with:
///
/// `cargo test --release -p ferrum2-crypto --test tcp_open_primitive_timing \
/// --locked -- --ignored --exact release_timing_copy_in_place_vs_out_of_place \
/// --nocapture --test-threads=1`
#[test]
#[ignore = "release-only primitive performance diagnostic"]
fn release_timing_copy_in_place_vs_out_of_place() {
    require_release_build();

    for (kind, label) in METHODS {
        let fixture = fixture(kind);
        let mut copy_output = vec![0_u8; PAYLOAD_BYTES];
        let mut into_output = vec![0_u8; PAYLOAD_BYTES];

        black_box(run_pair(
            &fixture,
            &mut copy_output,
            &mut into_output,
            WARMUP_ITERATIONS,
            false,
        ));

        let mut copy_samples = Vec::with_capacity(SAMPLES);
        let mut into_samples = Vec::with_capacity(SAMPLES);
        for sample in 0..SAMPLES {
            let candidate_first = sample % 2 == 1;
            let observation = run_pair(
                &fixture,
                &mut copy_output,
                &mut into_output,
                MEASURED_ITERATIONS,
                candidate_first,
            );
            let operations = MEASURED_ITERATIONS * 2;
            print_sample(label, sample + 1, candidate_first, operations, observation);
            copy_samples.push(observation.copy_in_place.elapsed);
            into_samples.push(observation.out_of_place.elapsed);
        }

        let copy_median = median(&mut copy_samples);
        let into_median = median(&mut into_samples);
        print_summary(label, MEASURED_ITERATIONS * 2, copy_median, into_median);
    }
}

fn fixture(kind: CipherKind) -> Fixture {
    let key = [0x5a; 32];
    let key = &key[..kind.key_len()];
    let encryptor = TcpCipher::try_from_subkey(kind, key).expect("fixture encryptor");
    let cipher = TcpCipher::try_from_subkey(kind, key).expect("fixture opener");
    let plaintext = (0..PAYLOAD_BYTES)
        .map(|index| ((index * 131 + 17) % 251 + 1) as u8)
        .collect::<Vec<_>>();
    let mut ciphertext = plaintext.clone();
    let tag = encryptor
        .encrypt_packet(&NONCE, &mut ciphertext)
        .expect("fixture encryption");

    let mut copy_output = ciphertext.clone();
    cipher
        .decrypt_packet(&NONCE, &mut copy_output, &tag)
        .expect("copy/in-place preflight");
    assert_eq!(copy_output, plaintext);

    let mut into_output = vec![0xa5; PAYLOAD_BYTES];
    cipher
        .decrypt_packet_into(&NONCE, &ciphertext, &mut into_output, &tag)
        .expect("out-of-place preflight");
    assert_eq!(into_output, plaintext);

    Fixture {
        cipher,
        ciphertext,
        tag,
        plaintext,
    }
}

fn run_pair(
    fixture: &Fixture,
    copy_output: &mut [u8],
    into_output: &mut [u8],
    iterations: usize,
    candidate_first: bool,
) -> PairObservation {
    let (copy_first, into_first, copy_second, into_second) = if candidate_first {
        let into_first = run_out_of_place(fixture, into_output, iterations);
        let copy_first = run_copy_in_place(fixture, copy_output, iterations);
        let copy_second = run_copy_in_place(fixture, copy_output, iterations);
        let into_second = run_out_of_place(fixture, into_output, iterations);
        (copy_first, into_first, copy_second, into_second)
    } else {
        let copy_first = run_copy_in_place(fixture, copy_output, iterations);
        let into_first = run_out_of_place(fixture, into_output, iterations);
        let into_second = run_out_of_place(fixture, into_output, iterations);
        let copy_second = run_copy_in_place(fixture, copy_output, iterations);
        (copy_first, into_first, copy_second, into_second)
    };

    PairObservation {
        copy_in_place: merge_batches(copy_first, copy_second),
        out_of_place: merge_batches(into_first, into_second),
    }
}

#[inline(never)]
fn run_copy_in_place(fixture: &Fixture, output: &mut [u8], iterations: usize) -> BatchObservation {
    let mut checksum = 0_u64;
    let started = Instant::now();
    for iteration in 0..iterations {
        output.copy_from_slice(black_box(fixture.ciphertext.as_slice()));
        let result = fixture.cipher.decrypt_packet(
            black_box(&NONCE),
            black_box(&mut *output),
            black_box(&fixture.tag),
        );
        black_box(result).expect("copy/in-place authentication");
        checksum =
            checksum.rotate_left(1) ^ u64::from(black_box(output[observation_index(iteration)]));
    }
    let elapsed = started.elapsed();

    black_box(checksum);
    assert_eq!(checksum, expected_checksum(&fixture.plaintext, iterations));
    assert_eq!(output, fixture.plaintext);
    BatchObservation { elapsed, checksum }
}

#[inline(never)]
fn run_out_of_place(fixture: &Fixture, output: &mut [u8], iterations: usize) -> BatchObservation {
    let mut checksum = 0_u64;
    let started = Instant::now();
    for iteration in 0..iterations {
        let result = fixture.cipher.decrypt_packet_into(
            black_box(&NONCE),
            black_box(fixture.ciphertext.as_slice()),
            black_box(&mut *output),
            black_box(&fixture.tag),
        );
        black_box(result).expect("out-of-place authentication");
        checksum =
            checksum.rotate_left(1) ^ u64::from(black_box(output[observation_index(iteration)]));
    }
    let elapsed = started.elapsed();

    black_box(checksum);
    assert_eq!(checksum, expected_checksum(&fixture.plaintext, iterations));
    assert_eq!(output, fixture.plaintext);
    BatchObservation { elapsed, checksum }
}

fn observation_index(iteration: usize) -> usize {
    iteration.wrapping_mul(4_093) & (PAYLOAD_BYTES - 1)
}

fn expected_checksum(plaintext: &[u8], iterations: usize) -> u64 {
    let mut checksum = 0_u64;
    for iteration in 0..iterations {
        checksum = checksum.rotate_left(1) ^ u64::from(plaintext[observation_index(iteration)]);
    }
    checksum
}

fn merge_batches(first: BatchObservation, second: BatchObservation) -> BatchObservation {
    BatchObservation {
        elapsed: first.elapsed + second.elapsed,
        checksum: first.checksum.wrapping_add(second.checksum),
    }
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn print_sample(
    label: &str,
    sample: usize,
    candidate_first: bool,
    operations: usize,
    observation: PairObservation,
) {
    println!(
        "tcp_open_primitive_sample cipher={label} payload_bytes={PAYLOAD_BYTES} sample={sample} \
         order={} operations_per_role={operations} copy_in_place_elapsed_ns={} \
         copy_in_place_ns_per_op={:.1} copy_in_place_gib_per_second={:.3} \
         out_of_place_elapsed_ns={} out_of_place_ns_per_op={:.1} \
         out_of_place_gib_per_second={:.3} paired_delta_percent={:.3} \
         copy_checksum={} into_checksum={}",
        if candidate_first { "baab" } else { "abba" },
        observation.copy_in_place.elapsed.as_nanos(),
        nanoseconds_per_operation(observation.copy_in_place.elapsed, operations),
        gibibytes_per_second(observation.copy_in_place.elapsed, operations),
        observation.out_of_place.elapsed.as_nanos(),
        nanoseconds_per_operation(observation.out_of_place.elapsed, operations),
        gibibytes_per_second(observation.out_of_place.elapsed, operations),
        paired_delta_percent(
            observation.copy_in_place.elapsed,
            observation.out_of_place.elapsed,
        ),
        observation.copy_in_place.checksum,
        observation.out_of_place.checksum,
    );
}

fn print_summary(label: &str, operations: usize, copy_median: Duration, into_median: Duration) {
    println!(
        "tcp_open_primitive_summary cipher={label} payload_bytes={PAYLOAD_BYTES} samples={SAMPLES} \
         operations_per_role_per_sample={operations} copy_in_place_median_elapsed_ns={} \
         copy_in_place_median_ns_per_op={:.1} copy_in_place_median_gib_per_second={:.3} \
         out_of_place_median_elapsed_ns={} out_of_place_median_ns_per_op={:.1} \
         out_of_place_median_gib_per_second={:.3} median_delta_percent={:.3}",
        copy_median.as_nanos(),
        nanoseconds_per_operation(copy_median, operations),
        gibibytes_per_second(copy_median, operations),
        into_median.as_nanos(),
        nanoseconds_per_operation(into_median, operations),
        gibibytes_per_second(into_median, operations),
        paired_delta_percent(copy_median, into_median),
    );
}

fn nanoseconds_per_operation(elapsed: Duration, operations: usize) -> f64 {
    elapsed.as_secs_f64() * 1_000_000_000.0 / operations as f64
}

fn gibibytes_per_second(elapsed: Duration, operations: usize) -> f64 {
    (PAYLOAD_BYTES * operations) as f64 / (1_024.0 * 1_024.0 * 1_024.0) / elapsed.as_secs_f64()
}

fn paired_delta_percent(copy_in_place: Duration, out_of_place: Duration) -> f64 {
    (out_of_place.as_secs_f64() / copy_in_place.as_secs_f64() - 1.0) * 100.0
}

#[cfg(debug_assertions)]
fn require_release_build() {
    panic!("this diagnostic must be run with cargo test --release");
}

#[cfg(not(debug_assertions))]
fn require_release_build() {}
