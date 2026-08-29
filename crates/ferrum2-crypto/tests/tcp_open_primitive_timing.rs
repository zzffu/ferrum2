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

const COLD_CORPUS_BYTES: usize = 64 * 1_024 * 1_024;
const COLD_EVICTION_BYTES: usize = 64 * 1_024 * 1_024;
const COLD_BLOCKS: usize = COLD_CORPUS_BYTES / PAYLOAD_BYTES;
const COLD_WARMUP_ITERATIONS: usize = 128;
const COLD_SAMPLES: usize = 9;
const _: () = {
    assert!(COLD_CORPUS_BYTES > 32 * 1_024 * 1_024);
    assert!(COLD_CORPUS_BYTES.is_multiple_of(PAYLOAD_BYTES));
    assert!(COLD_BLOCKS.is_power_of_two());
};

#[derive(Clone)]
struct ColdCorpus {
    ciphertexts: Vec<u8>,
    nonces: Vec<[u8; 12]>,
    tags: Vec<[u8; 16]>,
}

impl ColdCorpus {
    fn block(&self, index: usize) -> &[u8] {
        let start = index * PAYLOAD_BYTES;
        &self.ciphertexts[start..start + PAYLOAD_BYTES]
    }
}

struct ColdFixture {
    cipher: TcpCipher,
    copy_source: ColdCorpus,
    into_source: ColdCorpus,
    plaintext: Vec<u8>,
}

/// Diagnostic-only locality barrier for two valid AES-128 TCP open layouts.
/// Every timed source block is selected once from an independent corpus larger
/// than the measured host LLC. Each role traverses its own eviction buffer and
/// pre-touches its fixed output before timing starts.
///
/// Run with:
///
/// `cargo test --release -p ferrum2-crypto --test tcp_open_primitive_timing \
/// --locked -- --ignored --exact release_timing_cold_source_copy_in_place_vs_out_of_place \
/// --nocapture --test-threads=1`
#[test]
#[ignore = "release-only cold-source primitive performance diagnostic"]
fn release_timing_cold_source_copy_in_place_vs_out_of_place() {
    require_release_build();

    let fixture = cold_fixture();
    let mut copy_output = vec![0_u8; PAYLOAD_BYTES];
    let mut into_output = vec![0_u8; PAYLOAD_BYTES];
    let mut copy_eviction = vec![0x36_u8; COLD_EVICTION_BYTES];
    let mut into_eviction = vec![0xc9_u8; COLD_EVICTION_BYTES];

    black_box(run_cold_pair(
        &fixture,
        &mut copy_output,
        &mut into_output,
        &mut copy_eviction,
        &mut into_eviction,
        COLD_WARMUP_ITERATIONS,
        false,
    ));

    let mut copy_samples = Vec::with_capacity(COLD_SAMPLES);
    let mut into_samples = Vec::with_capacity(COLD_SAMPLES);
    for sample in 0..COLD_SAMPLES {
        let candidate_first = sample % 2 == 1;
        let observation = run_cold_pair(
            &fixture,
            &mut copy_output,
            &mut into_output,
            &mut copy_eviction,
            &mut into_eviction,
            COLD_BLOCKS,
            candidate_first,
        );
        let operations = COLD_BLOCKS * 2;
        print_cold_sample(sample + 1, candidate_first, operations, observation);
        copy_samples.push(observation.copy_in_place.elapsed);
        into_samples.push(observation.out_of_place.elapsed);
    }

    let copy_median = median(&mut copy_samples);
    let into_median = median(&mut into_samples);
    print_cold_summary(COLD_BLOCKS * 2, copy_median, into_median);
}

fn cold_fixture() -> ColdFixture {
    let key = [0x6a; 16];
    let encryptor = TcpCipher::try_from_subkey(CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &key)
        .expect("cold fixture encryptor");
    let cipher = TcpCipher::try_from_subkey(CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &key)
        .expect("cold fixture opener");
    let plaintext = (0..PAYLOAD_BYTES)
        .map(|index| ((index * 193 + 29) % 251 + 1) as u8)
        .collect::<Vec<_>>();
    let mut copy_source = ColdCorpus {
        ciphertexts: vec![0_u8; COLD_CORPUS_BYTES],
        nonces: Vec::with_capacity(COLD_BLOCKS),
        tags: Vec::with_capacity(COLD_BLOCKS),
    };

    for block in 0..COLD_BLOCKS {
        let start = block * PAYLOAD_BYTES;
        let ciphertext = &mut copy_source.ciphertexts[start..start + PAYLOAD_BYTES];
        ciphertext.copy_from_slice(&plaintext);
        let nonce = cold_nonce(block);
        let tag = encryptor
            .encrypt_packet(&nonce, ciphertext)
            .expect("cold fixture encryption");
        copy_source.nonces.push(nonce);
        copy_source.tags.push(tag);
    }

    let into_source = copy_source.clone();
    assert_ne!(
        copy_source.ciphertexts.as_ptr(),
        into_source.ciphertexts.as_ptr(),
        "cold roles require independent source allocations"
    );
    validate_cold_sources(&cipher, &copy_source, &into_source, &plaintext);

    ColdFixture {
        cipher,
        copy_source,
        into_source,
        plaintext,
    }
}

fn validate_cold_sources(
    cipher: &TcpCipher,
    copy_source: &ColdCorpus,
    into_source: &ColdCorpus,
    plaintext: &[u8],
) {
    let mut copy_output = vec![0_u8; PAYLOAD_BYTES];
    let mut into_output = vec![0_u8; PAYLOAD_BYTES];
    for block in 0..COLD_BLOCKS {
        copy_output.copy_from_slice(copy_source.block(block));
        cipher
            .decrypt_packet(
                &copy_source.nonces[block],
                &mut copy_output,
                &copy_source.tags[block],
            )
            .expect("cold copy/in-place preflight");
        assert_eq!(copy_output, plaintext);

        cipher
            .decrypt_packet_into(
                &into_source.nonces[block],
                into_source.block(block),
                &mut into_output,
                &into_source.tags[block],
            )
            .expect("cold out-of-place preflight");
        assert_eq!(into_output, plaintext);
    }
}

fn cold_nonce(block: usize) -> [u8; 12] {
    let mut nonce = [0xd3; 12];
    nonce[..8].copy_from_slice(&(block as u64).to_le_bytes());
    nonce
}

#[allow(clippy::too_many_arguments)]
fn run_cold_pair(
    fixture: &ColdFixture,
    copy_output: &mut [u8],
    into_output: &mut [u8],
    copy_eviction: &mut [u8],
    into_eviction: &mut [u8],
    iterations: usize,
    candidate_first: bool,
) -> PairObservation {
    let (copy_first, into_first, copy_second, into_second) = if candidate_first {
        let into_first = run_cold_out_of_place(fixture, into_output, into_eviction, iterations);
        let copy_first = run_cold_copy_in_place(fixture, copy_output, copy_eviction, iterations);
        let copy_second = run_cold_copy_in_place(fixture, copy_output, copy_eviction, iterations);
        let into_second = run_cold_out_of_place(fixture, into_output, into_eviction, iterations);
        (copy_first, into_first, copy_second, into_second)
    } else {
        let copy_first = run_cold_copy_in_place(fixture, copy_output, copy_eviction, iterations);
        let into_first = run_cold_out_of_place(fixture, into_output, into_eviction, iterations);
        let into_second = run_cold_out_of_place(fixture, into_output, into_eviction, iterations);
        let copy_second = run_cold_copy_in_place(fixture, copy_output, copy_eviction, iterations);
        (copy_first, into_first, copy_second, into_second)
    };

    PairObservation {
        copy_in_place: merge_batches(copy_first, copy_second),
        out_of_place: merge_batches(into_first, into_second),
    }
}

#[inline(never)]
fn run_cold_copy_in_place(
    fixture: &ColdFixture,
    output: &mut [u8],
    eviction: &mut [u8],
    iterations: usize,
) -> BatchObservation {
    assert!(iterations <= COLD_BLOCKS);
    black_box(prepare_cold_role(eviction, output));
    let mut checksum = 0_u64;
    let started = Instant::now();
    for iteration in 0..iterations {
        let block = cold_block_index(iteration);
        output.copy_from_slice(black_box(fixture.copy_source.block(block)));
        let result = fixture.cipher.decrypt_packet(
            black_box(&fixture.copy_source.nonces[block]),
            black_box(&mut *output),
            black_box(&fixture.copy_source.tags[block]),
        );
        black_box(result).expect("cold copy/in-place authentication");
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
fn run_cold_out_of_place(
    fixture: &ColdFixture,
    output: &mut [u8],
    eviction: &mut [u8],
    iterations: usize,
) -> BatchObservation {
    assert!(iterations <= COLD_BLOCKS);
    black_box(prepare_cold_role(eviction, output));
    let mut checksum = 0_u64;
    let started = Instant::now();
    for iteration in 0..iterations {
        let block = cold_block_index(iteration);
        let result = fixture.cipher.decrypt_packet_into(
            black_box(&fixture.into_source.nonces[block]),
            black_box(fixture.into_source.block(block)),
            black_box(&mut *output),
            black_box(&fixture.into_source.tags[block]),
        );
        black_box(result).expect("cold out-of-place authentication");
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
fn prepare_cold_role(eviction: &mut [u8], output: &mut [u8]) -> u64 {
    assert_eq!(eviction.len(), COLD_EVICTION_BYTES);
    assert_eq!(output.len(), PAYLOAD_BYTES);
    let mut checksum = 0_u64;
    for offset in (0..eviction.len()).step_by(64) {
        let next = black_box(eviction[offset]).wrapping_add(1);
        eviction[offset] = next;
        checksum = checksum.rotate_left(1) ^ u64::from(next);
    }
    for offset in (0..output.len()).step_by(64) {
        let next = black_box(output[offset]).wrapping_add(1);
        output[offset] = next;
        checksum = checksum.rotate_left(1) ^ u64::from(next);
    }
    black_box(checksum)
}

fn cold_block_index(iteration: usize) -> usize {
    iteration.wrapping_mul(1_031) & (COLD_BLOCKS - 1)
}

fn print_cold_sample(
    sample: usize,
    candidate_first: bool,
    operations: usize,
    observation: PairObservation,
) {
    println!(
        "tcp_open_cold_source_sample cipher=aes-128-gcm payload_bytes={PAYLOAD_BYTES} \
         corpus_bytes_per_role={COLD_CORPUS_BYTES} eviction_bytes_per_role={COLD_EVICTION_BYTES} \
         sample={sample} order={} operations_per_role={operations} \
         copy_in_place_elapsed_ns={} copy_in_place_ns_per_op={:.1} \
         copy_in_place_gib_per_second={:.3} out_of_place_elapsed_ns={} \
         out_of_place_ns_per_op={:.1} out_of_place_gib_per_second={:.3} \
         paired_delta_percent={:.3} copy_checksum={} into_checksum={}",
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

fn print_cold_summary(operations: usize, copy_median: Duration, into_median: Duration) {
    println!(
        "tcp_open_cold_source_summary cipher=aes-128-gcm payload_bytes={PAYLOAD_BYTES} \
         corpus_bytes_per_role={COLD_CORPUS_BYTES} eviction_bytes_per_role={COLD_EVICTION_BYTES} \
         samples={COLD_SAMPLES} blocks_per_batch={COLD_BLOCKS} \
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
