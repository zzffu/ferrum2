#![forbid(unsafe_code)]

use std::alloc::System;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::fs;
use std::hint::black_box;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use ferrum2_core::route::Network;
use ferrum2_core::{CanonicalDomain, DomainName, TargetAddr};
use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheKey, DnsCacheQtype, DnsPolicyAction,
    DnsPolicyMatcher, DnsPolicyProgram, DnsPolicyQuery, DnsPolicyRoute, DnsPolicyRule,
    DnsPolicyStep, DnsServerId, DnsStrategy, ResolverGeneration,
};
use ferrum2_rule::srs::{SrsStatistics, decode_srs};
use ferrum2_rule::{
    CompiledMatchSet, MatchSetBuilder, MatchSetCapabilities, MatchSetId, OrderedRouteProgram,
    OrderedRouteRule, RouteMatchField, RouteMatchObservation, RouteMatchSource, RouteMatchType,
    RouteMatcher, RouteMetadata, RouteProgramAction, RouteRuleAction, RuleEngineSnapshot,
    RuleEngineSnapshotBuilder, RuleProgramMode,
};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stats_alloc::{Region, StatsAlloc};

#[global_allocator]
static GLOBAL_ALLOCATOR: StatsAlloc<System> = StatsAlloc::system();

const REPORT_SCHEMA: &str = "ferrum2.rule-qualification.v1";
const DEFAULT_SMOKE_SAMPLES: usize = 101;
const DEFAULT_QUALIFICATION_SAMPLES: usize = 101;
const MIN_SAMPLES: usize = 5;
const MAX_SAMPLES: usize = 1_001;
const MAX_BASE_ITERATIONS: u64 = 10_000_000;
const MAX_CALIBRATED_ITERATIONS: u64 = 1_000_000_000;
const MIN_SAMPLE_WINDOW: Duration = Duration::from_micros(100);
const MIN_SAMPLE_WINDOW_NANOSECONDS: u64 = MIN_SAMPLE_WINDOW.as_micros() as u64 * 1_000;
const WARMUP_BATCHES: usize = 5;
const PAIRED_ROUNDS_PER_SAMPLE: u64 = 32;
const ALLOCATION_SAMPLES: usize = 5;
const LOCAL_PARITY_TARGET_PERCENT: f64 = 5.0;
const NOISY_GATE_CEILING_PERCENT: f64 = 10.0;
const P99_PARITY_TARGET_PERCENT: f64 = 15.0;
const SYNTHETIC_SRS_VERSION: u8 = 2;
const SRS_ITEM_DOMAIN: u8 = 2;
const SRS_ITEM_DOMAIN_KEYWORD: u8 = 3;
const SRS_ITEM_IP_CIDR: u8 = 6;
const SRS_ITEM_FINAL: u8 = 0xff;
const SRS_DOMAIN_SUFFIX_MARKER: u8 = b'\n';

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Smoke,
    Qualification,
}

impl Profile {
    fn match_sizes(self) -> Vec<usize> {
        match self {
            Self::Smoke => vec![100],
            Self::Qualification => vec![100, 1_000, 10_000],
        }
    }

    fn route_sizes(self) -> Vec<usize> {
        match self {
            Self::Smoke => vec![1, 32, 64],
            Self::Qualification => vec![1, 32, 64, 1_000, 10_000],
        }
    }

    fn dns_rule_sizes(self) -> Vec<usize> {
        match self {
            Self::Smoke => vec![1],
            Self::Qualification => vec![1, 64, 65, 100, 1_000, 10_000],
        }
    }

    const fn default_samples(self) -> usize {
        match self {
            Self::Smoke => DEFAULT_SMOKE_SAMPLES,
            Self::Qualification => DEFAULT_QUALIFICATION_SAMPLES,
        }
    }

    const fn default_base_iterations(self) -> u64 {
        match self {
            Self::Smoke | Self::Qualification => 8_192,
        }
    }

    const fn includes_generated_binary_srs(self) -> bool {
        matches!(self, Self::Qualification)
    }
}

/// Reproducible rule and DNS-policy qualification runner.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Args {
    /// Bounded scenario matrix. Qualification adds the 1k/10k scales.
    #[arg(long, value_enum, default_value_t = Profile::Smoke)]
    pub profile: Profile,

    /// Explicitly append the expensive 100,000-value MatchSet scale.
    #[arg(long)]
    pub include_100k: bool,

    /// Odd or even independent timing samples retained verbatim in JSON.
    #[arg(long)]
    pub samples: Option<usize>,

    /// Base operations per timing sample; large programs are scaled down.
    #[arg(long)]
    pub iterations_per_sample: Option<u64>,

    /// Workspace containing Cargo.toml and tests/fixtures/srs.
    #[arg(long, default_value = ".")]
    pub workspace_root: PathBuf,

    /// Optionally write the exact stdout JSON bytes to this file.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug)]
pub struct QualificationError(String);

impl QualificationError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for QualificationError {}

type Result<T> = std::result::Result<T, QualificationError>;

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    generated_unix_millis: u128,
    profile: Profile,
    environment: EnvironmentFingerprint,
    repository: RepositoryFingerprint,
    runner: RunnerFingerprint,
    configuration: RunConfiguration,
    measurement_policy: MeasurementPolicy,
    fixtures: Vec<FixtureEvidence>,
    measurements: Vec<Measurement>,
    parity_observations: Vec<ParityObservation>,
    scenario_count: usize,
    correctness_passed: bool,
    allocation_gate_passed: bool,
    parity_gate_passed: bool,
    thresholds_passed: bool,
}

#[derive(Serialize)]
struct EnvironmentFingerprint {
    os: &'static str,
    architecture: &'static str,
    family: &'static str,
    logical_cpus: usize,
    cpu_model: Option<String>,
    rustc_version: Option<String>,
    timer: &'static str,
    build_profile: &'static str,
}

#[derive(Serialize)]
struct RepositoryFingerprint {
    git_head: Option<String>,
    git_tree: Option<String>,
    tree_state: &'static str,
    changed_entries: Option<usize>,
    status_sha256: Option<String>,
}

#[derive(Serialize)]
struct RunnerFingerprint {
    sha256: String,
    bytes: u64,
}

#[derive(Serialize)]
struct RunConfiguration {
    match_sizes: Vec<usize>,
    route_sizes: Vec<usize>,
    dns_rule_sizes: Vec<usize>,
    samples: usize,
    base_iterations_per_sample: u64,
    includes_100k: bool,
}

#[derive(Serialize)]
struct MeasurementPolicy {
    latency_source: &'static str,
    minimum_reported_batch_nanoseconds: u64,
    calibration: &'static str,
    warmup_batches: usize,
    paired_order: &'static str,
    retained_samples: bool,
    allocation_measurement: &'static str,
    compiled_memory_measurement: &'static str,
    local_parity_target_percent: f64,
    noisy_gate_ceiling_percent: f64,
    p99_parity_target_percent: f64,
    thresholds_enforced_by_runner: bool,
    parity_gate_scope: &'static str,
    paired_observation_scope: &'static str,
    allocation_gate_scope: &'static str,
    note: &'static str,
}

#[derive(Serialize)]
struct FixtureEvidence {
    name: String,
    provenance: &'static str,
    bytes: u64,
    sha256: String,
    srs_version: u8,
    statistics: SerializableSrsStatistics,
    capabilities: SerializableCapabilities,
}

#[derive(Serialize)]
struct SerializableSrsStatistics {
    rules: u64,
    exact_domains: usize,
    domain_suffixes: usize,
    domain_keywords: usize,
    ip_cidrs: usize,
}

impl From<SrsStatistics> for SerializableSrsStatistics {
    fn from(value: SrsStatistics) -> Self {
        Self {
            rules: value.rules,
            exact_domains: value.exact_domains,
            domain_suffixes: value.domain_suffixes,
            domain_keywords: value.domain_keywords,
            ip_cidrs: value.ip_cidrs,
        }
    }
}

#[derive(Serialize)]
struct SerializableCapabilities {
    exact_domain: bool,
    domain_suffix: bool,
    domain_keyword: bool,
    ip_cidr: bool,
}

impl From<MatchSetCapabilities> for SerializableCapabilities {
    fn from(value: MatchSetCapabilities) -> Self {
        Self {
            exact_domain: value.exact_domain,
            domain_suffix: value.domain_suffix,
            domain_keyword: value.domain_keyword,
            ip_cidr: value.ip_cidr,
        }
    }
}

#[derive(Serialize)]
struct Measurement {
    id: String,
    suite: &'static str,
    source: String,
    scenario: String,
    scale: usize,
    fixture: Option<String>,
    rule_program_mode: Option<&'static str>,
    query_candidate_visits: Option<usize>,
    requested_min_iterations_per_sample: u64,
    actual_iterations_per_sample: Vec<u64>,
    sample_batch_nanoseconds: Vec<u64>,
    timing_pair_id: Option<String>,
    paired_sample_order: Option<Vec<&'static str>>,
    samples_ns_per_op: Vec<f64>,
    p50_ns_per_op: f64,
    p99_ns_per_op: f64,
    queries_per_second_from_p50: Option<f64>,
    build_nanoseconds: u128,
    compiled_allocations: u64,
    compiled_reallocations: u64,
    compiled_entries: Option<usize>,
    compiled_bytes_per_entry: Option<f64>,
    allocation_samples: Vec<AllocationSample>,
    allocations_per_op: f64,
    reallocations_per_op: f64,
    bytes_allocated_per_op: f64,
    bytes_deallocated_per_op: f64,
    compiled_memory_bytes: u64,
    allocation_status: &'static str,
    compiled_memory_status: &'static str,
    allocation_gate_applicable: bool,
    allocation_gate_passed: Option<bool>,
    correctness: &'static str,
    outcome_checksum: u64,
}

#[derive(Serialize)]
struct ParityObservation {
    suite: &'static str,
    scenario: String,
    scale: usize,
    baseline_id: String,
    candidate_id: String,
    median_delta_percent: Option<f64>,
    p99_delta_percent: Option<f64>,
    median_limit_percent: f64,
    p99_limit_percent: f64,
    performance_gate_applicable: bool,
    decision: &'static str,
}

struct BenchResult {
    samples: Vec<f64>,
    actual_iterations_per_sample: Vec<u64>,
    sample_batch_nanoseconds: Vec<u64>,
    timing_pair_id: Option<String>,
    paired_sample_order: Option<Vec<&'static str>>,
    p50: f64,
    p99: f64,
    checksum: u64,
    allocation_samples: Vec<AllocationSample>,
    allocations_per_op: f64,
    reallocations_per_op: f64,
    bytes_allocated_per_op: f64,
    bytes_deallocated_per_op: f64,
    allocation_free: bool,
}

struct AllocationEvidence {
    samples: Vec<AllocationSample>,
    allocations_per_op: f64,
    reallocations_per_op: f64,
    bytes_allocated_per_op: f64,
    bytes_deallocated_per_op: f64,
    allocation_free: bool,
    checksum: u64,
}

#[derive(Serialize)]
struct AllocationSample {
    iterations: u64,
    allocations: u64,
    deallocations: u64,
    reallocations: u64,
    bytes_allocated: u64,
    bytes_deallocated: u64,
}

#[derive(Clone, Copy)]
struct BuildEvidence {
    nanoseconds: u128,
    allocations: u64,
    reallocations: u64,
    net_retained_bytes: u64,
}

impl BuildEvidence {
    fn combined(self, other: Self) -> Self {
        Self {
            nanoseconds: self.nanoseconds.saturating_add(other.nanoseconds),
            allocations: self.allocations.saturating_add(other.allocations),
            reallocations: self.reallocations.saturating_add(other.reallocations),
            net_retained_bytes: self
                .net_retained_bytes
                .saturating_add(other.net_retained_bytes),
        }
    }
}

pub fn execute(args: Args) -> Result<()> {
    let samples = args.samples.unwrap_or(args.profile.default_samples());
    if !(MIN_SAMPLES..=MAX_SAMPLES).contains(&samples) {
        return Err(QualificationError::new(format!(
            "--samples must be in {MIN_SAMPLES}..={MAX_SAMPLES}"
        )));
    }
    let base_iterations = args
        .iterations_per_sample
        .unwrap_or(args.profile.default_base_iterations());
    if !(1..=MAX_BASE_ITERATIONS).contains(&base_iterations) {
        return Err(QualificationError::new(format!(
            "--iterations-per-sample must be in 1..={MAX_BASE_ITERATIONS}"
        )));
    }

    let workspace_root = fs::canonicalize(&args.workspace_root).map_err(|error| {
        QualificationError::new(format!("workspace root is unavailable: {error}"))
    })?;
    validate_workspace_root(&workspace_root)?;

    let mut match_sizes = args.profile.match_sizes();
    if args.include_100k && !match_sizes.contains(&100_000) {
        match_sizes.push(100_000);
    }
    let route_sizes = args.profile.route_sizes();
    let dns_rule_sizes = args.profile.dns_rule_sizes();

    let environment = environment_fingerprint();
    let repository = repository_fingerprint(&workspace_root);
    let runner = runner_fingerprint()?;
    let mut measurements = Vec::new();
    run_generated_match_sets(&match_sizes, samples, base_iterations, &mut measurements)?;
    let mut fixtures = Vec::new();
    if args.profile.includes_generated_binary_srs() {
        fixtures.extend(run_generated_binary_srs(
            &match_sizes,
            samples,
            base_iterations,
            &mut measurements,
        )?);
    }
    fixtures.extend(run_real_srs(
        &workspace_root,
        samples,
        base_iterations,
        &mut measurements,
    )?);
    run_route_programs(&route_sizes, samples, base_iterations, &mut measurements)?;
    run_dns_policy(&dns_rule_sizes, samples, base_iterations, &mut measurements)?;
    ensure_unique_measurement_ids(&measurements)?;
    let parity_observations = collect_parity_observations(&measurements)?;
    let parity_gate_passed = parity_observations.iter().all(|observation| {
        !observation.performance_gate_applicable || observation.decision == "passed"
    });
    let allocation_gate_passed = measurements
        .iter()
        .all(|row| !row.allocation_gate_applicable || row.allocation_gate_passed == Some(true));

    let report = Report {
        schema: REPORT_SCHEMA,
        generated_unix_millis: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| QualificationError::new("system clock precedes the Unix epoch"))?
            .as_millis(),
        profile: args.profile,
        environment,
        repository,
        runner,
        configuration: RunConfiguration {
            match_sizes,
            route_sizes,
            dns_rule_sizes,
            samples,
            base_iterations_per_sample: base_iterations,
            includes_100k: args.include_100k,
        },
        measurement_policy: MeasurementPolicy {
            latency_source: "std::time::Instant self-calibrating wall-clock batches",
            minimum_reported_batch_nanoseconds: MIN_SAMPLE_WINDOW_NANOSECONDS,
            calibration: "each retained sample runs enough operations to reach the minimum window; paired rows share the same operation count",
            warmup_batches: WARMUP_BATCHES,
            paired_order: "each paired MatchSet sample contains 32 strictly alternating rounds (16 in each order); a deterministic scenario hash randomizes the first role",
            retained_samples: true,
            allocation_measurement: "stats_alloc 0.1.10 instrumented system allocator; five separate one-operation regions outside latency timing",
            compiled_memory_measurement: "net retained bytes in the instrumented build region",
            local_parity_target_percent: LOCAL_PARITY_TARGET_PERCENT,
            noisy_gate_ceiling_percent: NOISY_GATE_CEILING_PERCENT,
            p99_parity_target_percent: P99_PARITY_TARGET_PERCENT,
            thresholds_enforced_by_runner: true,
            parity_gate_scope: "CompiledMatchSet ordinary-inline/synthetic and synthetic/binary-SRS rows only",
            paired_observation_scope: "Route and DNS program ordinary/RuleSet rows retain paired latency and correctness but are not subject to the MatchSet 5%/15% gate",
            allocation_gate_scope: "CompiledMatchSet matches and Route evaluation with reusable scratch",
            note: "DNS end-to-end rows include query construction and report allocations without applying the matcher hot-path gate",
        },
        scenario_count: measurements.len(),
        fixtures,
        measurements,
        parity_observations,
        correctness_passed: true,
        allocation_gate_passed,
        parity_gate_passed,
        thresholds_passed: allocation_gate_passed && parity_gate_passed,
    };
    let mut encoded = serde_json::to_vec_pretty(&report)
        .map_err(|error| QualificationError::new(format!("JSON encoding failed: {error}")))?;
    encoded.push(b'\n');
    if let Some(output) = args.output.as_deref() {
        write_report(output, &encoded)?;
    }
    print!("{}", String::from_utf8_lossy(&encoded));
    if allocation_gate_passed && parity_gate_passed {
        Ok(())
    } else if !parity_gate_passed {
        Err(QualificationError::new(
            "ordinary/RuleSet local 5% median or 15% p99 parity gate failed; JSON evidence was emitted",
        ))
    } else {
        Err(QualificationError::new(
            "allocation-free MatchSet/Route hot-path gate failed; JSON evidence was emitted",
        ))
    }
}

fn validate_workspace_root(root: &Path) -> Result<()> {
    if !root.join("Cargo.toml").is_file() || !root.join("tests/fixtures/srs").is_dir() {
        return Err(QualificationError::new(
            "workspace root must contain Cargo.toml and tests/fixtures/srs",
        ));
    }
    Ok(())
}

fn write_report(path: &Path, encoded: &[u8]) -> Result<()> {
    if path.extension().and_then(|value| value.to_str()) != Some("json") {
        return Err(QualificationError::new(
            "--output must have a .json extension",
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(QualificationError::new(
            "--output parent directory does not exist",
        ));
    }
    fs::write(path, encoded)
        .map_err(|error| QualificationError::new(format!("report write failed: {error}")))
}

fn environment_fingerprint() -> EnvironmentFingerprint {
    EnvironmentFingerprint {
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        family: std::env::consts::FAMILY,
        logical_cpus: std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1),
        cpu_model: std::env::var("PROCESSOR_IDENTIFIER")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        rustc_version: command_text(Path::new("."), "rustc", &["--version"]),
        timer: "std::time::Instant",
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    }
}

fn repository_fingerprint(root: &Path) -> RepositoryFingerprint {
    let git_head = command_text(root, "git", &["rev-parse", "HEAD"]);
    let git_tree = command_text(root, "git", &["rev-parse", "HEAD^{tree}"]);
    let status = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout);
    let changed_entries = status.as_ref().map(|bytes| {
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count()
    });
    let status_sha256 = status.as_ref().map(|bytes| sha256_bytes(bytes));
    let tree_state = match changed_entries {
        Some(0) => "clean",
        Some(_) => "dirty",
        None => "unknown",
    };
    RepositoryFingerprint {
        git_head,
        git_tree,
        tree_state,
        changed_entries,
        status_sha256,
    }
}

fn runner_fingerprint() -> Result<RunnerFingerprint> {
    let executable = std::env::current_exe()
        .map_err(|error| QualificationError::new(format!("runner path unavailable: {error}")))?;
    let bytes = fs::metadata(&executable)
        .map_err(|error| QualificationError::new(format!("runner metadata unavailable: {error}")))?
        .len();
    Ok(RunnerFingerprint {
        sha256: sha256_file(&executable)?,
        bytes,
    })
}

fn command_text(root: &Path, program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .map_err(|error| QualificationError::new(format!("hash input unavailable: {error}")))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| QualificationError::new(format!("hash input read failed: {error}")))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn benchmark(
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

fn benchmark_pair(
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

fn benchmark_operation_pair(
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

fn warm_up_operation(operation: &mut impl FnMut() -> u64, iterations: u64) -> u64 {
    let mut checksum = 0_u64;
    for _ in 0..iterations.min(32) {
        checksum = checksum.rotate_left(1) ^ black_box(operation());
    }
    checksum
}

fn warm_up_pair_operation(set: &CompiledMatchSet, probe: &MatchProbe, iterations: u64) -> u64 {
    let mut checksum = 0_u64;
    for _ in 0..iterations.min(32) {
        checksum = checksum.rotate_left(1) ^ black_box(u64::from(probe_matches(set, probe)));
    }
    checksum
}

fn calibrate_iterations(
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

fn calibrate_pair_iterations(
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

fn timed_batch(operation: &mut impl FnMut() -> u64, iterations: u64, checksum: &mut u64) -> u64 {
    let started = Instant::now();
    for _ in 0..iterations {
        *checksum = checksum.rotate_left(1) ^ black_box(operation());
    }
    elapsed_nanoseconds(started)
}

fn timed_pair(
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
fn timed_pair_role(
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

fn timed_pair_sample(
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

fn timed_operation_pair(
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

fn timed_operation_pair_sample(
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

fn elapsed_nanoseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn grow_iterations_if_needed(iterations: u64, elapsed_nanoseconds: u64) -> u64 {
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

fn stable_order_seed(pair_id: &str) -> bool {
    let hash = pair_id
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    hash & 1 != 0
}

fn measure_allocations(
    operation: &mut impl FnMut() -> u64,
    mut checksum: u64,
) -> AllocationEvidence {
    let mut allocation_samples = Vec::with_capacity(ALLOCATION_SAMPLES);
    let mut total_allocations = 0_u128;
    let mut total_reallocations = 0_u128;
    let mut total_bytes_allocated = 0_u128;
    let mut total_bytes_deallocated = 0_u128;
    for _ in 0..ALLOCATION_SAMPLES {
        let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
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

fn measure_pair_allocations(
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
        let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
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

fn bench_result(
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

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn finish_build(started: Instant, region: &Region<'_, System>) -> Result<BuildEvidence> {
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

fn nearest_rank(values: &[f64], percentile: usize) -> f64 {
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let rank = (percentile * ordered.len()).div_ceil(100);
    ordered[rank.saturating_sub(1)]
}

#[allow(clippy::too_many_arguments)]
fn measurement(
    id: String,
    suite: &'static str,
    source: impl Into<String>,
    scenario: impl Into<String>,
    scale: usize,
    fixture: Option<String>,
    rule_program_mode: Option<RuleProgramMode>,
    requested_iterations: u64,
    build: BuildEvidence,
    compiled_entries: Option<usize>,
    result: BenchResult,
) -> Measurement {
    let allocation_gate_applicable = matches!(suite, "match_set" | "route_program");
    let allocation_gate_passed = allocation_gate_applicable.then_some(result.allocation_free);
    Measurement {
        id,
        suite,
        source: source.into(),
        scenario: scenario.into(),
        scale,
        fixture,
        rule_program_mode: rule_program_mode.map(|mode| match mode {
            RuleProgramMode::SmallLinear => "small_linear",
            RuleProgramMode::Indexed => "indexed",
        }),
        query_candidate_visits: None,
        requested_min_iterations_per_sample: requested_iterations,
        actual_iterations_per_sample: result.actual_iterations_per_sample,
        sample_batch_nanoseconds: result.sample_batch_nanoseconds,
        timing_pair_id: result.timing_pair_id,
        paired_sample_order: result.paired_sample_order,
        samples_ns_per_op: result.samples,
        p50_ns_per_op: result.p50,
        p99_ns_per_op: result.p99,
        queries_per_second_from_p50: (suite == "dns_policy" && result.p50 != 0.0)
            .then(|| 1_000_000_000_f64 / result.p50),
        build_nanoseconds: build.nanoseconds,
        compiled_allocations: build.allocations,
        compiled_reallocations: build.reallocations,
        compiled_entries,
        compiled_bytes_per_entry: compiled_entries
            .filter(|entries| *entries != 0)
            .map(|entries| build.net_retained_bytes as f64 / entries as f64),
        allocation_samples: result.allocation_samples,
        allocations_per_op: result.allocations_per_op,
        reallocations_per_op: result.reallocations_per_op,
        bytes_allocated_per_op: result.bytes_allocated_per_op,
        bytes_deallocated_per_op: result.bytes_deallocated_per_op,
        compiled_memory_bytes: build.net_retained_bytes,
        allocation_status: "measured",
        compiled_memory_status: "measured_net_retained_bytes",
        allocation_gate_applicable,
        allocation_gate_passed,
        correctness: "passed",
        outcome_checksum: result.checksum,
    }
}

fn ensure_unique_measurement_ids(measurements: &[Measurement]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for row in measurements {
        if !ids.insert(&row.id) {
            return Err(QualificationError::new(
                "qualification produced a duplicate measurement id",
            ));
        }
    }
    Ok(())
}

fn collect_parity_observations(measurements: &[Measurement]) -> Result<Vec<ParityObservation>> {
    let by_id: BTreeMap<&str, &Measurement> = measurements
        .iter()
        .map(|measurement| (measurement.id.as_str(), measurement))
        .collect();
    let mut observations = Vec::new();
    for (suite, baseline_source, candidate_source) in [
        ("match_set", "ordinary_inline", "synthetic_ruleset"),
        ("match_set", "synthetic_srs", "binary_srs"),
        ("route_program", "ordinary_only", "ruleset_only"),
        ("dns_policy", "ordinary_inline", "ruleset"),
    ] {
        for baseline in measurements
            .iter()
            .filter(|row| row.suite == suite && row.source == baseline_source)
        {
            let candidate_id = baseline.id.replace(
                &format!("/{baseline_source}/"),
                &format!("/{candidate_source}/"),
            );
            let candidate = by_id.get(candidate_id.as_str()).ok_or_else(|| {
                QualificationError::new(format!(
                    "{suite} {candidate_source} parity counterpart is missing"
                ))
            })?;
            if baseline.timing_pair_id.is_none()
                || baseline.timing_pair_id != candidate.timing_pair_id
                || baseline.actual_iterations_per_sample != candidate.actual_iterations_per_sample
                || baseline.paired_sample_order != candidate.paired_sample_order
            {
                return Err(QualificationError::new(format!(
                    "{suite} {baseline_source}/{candidate_source} rows do not share paired timing evidence"
                )));
            }
            let median_delta_percent =
                percent_delta(baseline.p50_ns_per_op, candidate.p50_ns_per_op);
            let p99_delta_percent = percent_delta(baseline.p99_ns_per_op, candidate.p99_ns_per_op);
            let performance_gate_applicable = suite == "match_set";
            let passed = within_limit(median_delta_percent, LOCAL_PARITY_TARGET_PERCENT)
                && within_limit(p99_delta_percent, P99_PARITY_TARGET_PERCENT);
            observations.push(ParityObservation {
                suite: baseline.suite,
                scenario: baseline.scenario.clone(),
                scale: baseline.scale,
                baseline_id: baseline.id.clone(),
                candidate_id,
                median_delta_percent,
                p99_delta_percent,
                median_limit_percent: LOCAL_PARITY_TARGET_PERCENT,
                p99_limit_percent: P99_PARITY_TARGET_PERCENT,
                performance_gate_applicable,
                decision: if !performance_gate_applicable {
                    "observed"
                } else if passed {
                    "passed"
                } else {
                    "failed"
                },
            });
        }
    }
    Ok(observations)
}

fn within_limit(delta: Option<f64>, limit: f64) -> bool {
    delta.is_some_and(|value| value.abs() <= limit)
}

fn percent_delta(baseline: f64, candidate: f64) -> Option<f64> {
    if baseline == 0.0 {
        return None;
    }
    Some((candidate - baseline) * 100.0 / baseline)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MatcherKind {
    Exact,
    Suffix,
    Keyword,
    CidrV4,
    CidrV6,
    Mixed,
}

impl MatcherKind {
    const ALL: [Self; 6] = [
        Self::Exact,
        Self::Suffix,
        Self::Keyword,
        Self::CidrV4,
        Self::CidrV6,
        Self::Mixed,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Suffix => "suffix",
            Self::Keyword => "keyword",
            Self::CidrV4 => "cidr_ipv4",
            Self::CidrV6 => "cidr_ipv6",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Clone)]
enum MatchProbe {
    Domain(CanonicalDomain),
    Ip(IpAddr),
}

struct ProbeCase {
    name: &'static str,
    probe: MatchProbe,
    expected: bool,
}

enum CompiledSetOwner {
    Direct(Arc<CompiledMatchSet>),
    Snapshot {
        snapshot: RuleEngineSnapshot,
        match_set: MatchSetId,
    },
}

impl CompiledSetOwner {
    fn compiled(&self) -> &CompiledMatchSet {
        match self {
            Self::Direct(set) => set,
            Self::Snapshot {
                snapshot,
                match_set,
            } => snapshot
                .match_set(*match_set)
                .expect("registered synthetic MatchSet"),
        }
    }
}

fn run_generated_match_sets(
    sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &scale in sizes {
        for kind in MatcherKind::ALL {
            let (ordinary, synthetic) = build_generated_match_set_pair(kind, scale)?;
            for case in match_probe_cases(kind, scale)? {
                let ordinary_set = ordinary.0.compiled();
                let synthetic_set = synthetic.0.compiled();
                if probe_matches(ordinary_set, &case.probe) != case.expected {
                    return Err(QualificationError::new(format!(
                        "generated ordinary_inline {}/{scale}/{} correctness check failed",
                        kind.name(),
                        case.name
                    )));
                }
                if probe_matches(synthetic_set, &case.probe) != case.expected {
                    return Err(QualificationError::new(format!(
                        "generated synthetic_ruleset {}/{scale}/{} correctness check failed",
                        kind.name(),
                        case.name
                    )));
                }
                let scenario = format!("{}/{}", kind.name(), case.name);
                let pair_id = format!("match_set/{scale}/{scenario}");
                let (ordinary_result, synthetic_result) = benchmark_pair(
                    ordinary_set,
                    synthetic_set,
                    &case.probe,
                    samples,
                    base_iterations,
                    pair_id,
                );
                measurements.push(measurement(
                    format!("match_set/ordinary_inline/{scale}/{scenario}"),
                    "match_set",
                    "ordinary_inline",
                    scenario.clone(),
                    scale,
                    None,
                    None,
                    base_iterations,
                    ordinary.1,
                    Some(ordinary_set.entry_counts().total()),
                    ordinary_result,
                ));
                measurements.push(measurement(
                    format!("match_set/synthetic_ruleset/{scale}/{scenario}"),
                    "match_set",
                    "synthetic_ruleset",
                    scenario,
                    scale,
                    None,
                    None,
                    base_iterations,
                    synthetic.1,
                    Some(synthetic_set.entry_counts().total()),
                    synthetic_result,
                ));
            }
        }
    }
    Ok(())
}

fn build_generated_match_set_pair(
    kind: MatcherKind,
    scale: usize,
) -> Result<(
    (CompiledSetOwner, BuildEvidence),
    (CompiledSetOwner, BuildEvidence),
)> {
    let ordinary_region = Region::new(&GLOBAL_ALLOCATOR);
    let ordinary_started = Instant::now();
    let compiled = Arc::new(compile_generated_match_set(kind, scale)?);
    let ordinary = CompiledSetOwner::Direct(Arc::clone(&compiled));
    let ordinary_build = finish_build(ordinary_started, &ordinary_region)?;

    let synthetic_region = Region::new(&GLOBAL_ALLOCATOR);
    let synthetic_started = Instant::now();
    let mut snapshot = RuleEngineSnapshotBuilder::new(1);
    let match_set = snapshot
        .add_shared_match_set(compiled)
        .map_err(|error| QualificationError::new(format!("snapshot add failed: {error}")))?;
    snapshot
        .add_rule_set("synthetic", match_set)
        .map_err(|error| QualificationError::new(format!("RuleSet add failed: {error}")))?;
    let synthetic = CompiledSetOwner::Snapshot {
        snapshot: snapshot
            .build()
            .map_err(|error| QualificationError::new(format!("snapshot build failed: {error}")))?,
        match_set,
    };
    let wrapper_build = finish_build(synthetic_started, &synthetic_region)?;
    Ok((
        (ordinary, ordinary_build),
        (synthetic, ordinary_build.combined(wrapper_build)),
    ))
}

#[cfg(test)]
fn build_generated_match_set(
    kind: MatcherKind,
    scale: usize,
    synthetic: bool,
) -> Result<(CompiledSetOwner, BuildEvidence)> {
    let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
    let started = Instant::now();
    let compiled = compile_generated_match_set(kind, scale)?;
    let owner = if synthetic {
        let mut snapshot = RuleEngineSnapshotBuilder::new(1);
        let match_set = snapshot
            .add_match_set(compiled)
            .map_err(|error| QualificationError::new(format!("snapshot add failed: {error}")))?;
        snapshot
            .add_rule_set("synthetic", match_set)
            .map_err(|error| QualificationError::new(format!("RuleSet add failed: {error}")))?;
        CompiledSetOwner::Snapshot {
            snapshot: snapshot.build().map_err(|error| {
                QualificationError::new(format!("snapshot build failed: {error}"))
            })?,
            match_set,
        }
    } else {
        CompiledSetOwner::Direct(Arc::new(compiled))
    };
    let build = finish_build(started, &allocation_region)?;
    Ok((owner, build))
}

fn compile_generated_match_set(kind: MatcherKind, scale: usize) -> Result<CompiledMatchSet> {
    let mut builder = MatchSetBuilder::new();
    for index in 0..scale {
        add_generated_value(&mut builder, kind, index)?;
    }
    builder
        .build()
        .map_err(|error| QualificationError::new(format!("MatchSet build failed: {error}")))
}

fn add_generated_value(
    builder: &mut MatchSetBuilder,
    kind: MatcherKind,
    index: usize,
) -> Result<()> {
    let selected = selected_matcher_kind(kind, index);
    let result = match selected {
        MatcherKind::Exact => builder.add_exact_domain(&format!("exact-{index}.bench.invalid")),
        MatcherKind::Suffix => builder.add_domain_suffix(&format!("suffix-{index}.bench.invalid")),
        MatcherKind::Keyword => builder.add_domain_keyword(&format!("needle{index}x")),
        MatcherKind::CidrV4 => builder.add_ip_cidr(IpNet::V4(generated_v4(index)?)),
        MatcherKind::CidrV6 => builder.add_ip_cidr(IpNet::V6(generated_v6(index)?)),
        MatcherKind::Mixed => unreachable!("mixed is reduced to one concrete category"),
    };
    result
        .map(|_| ())
        .map_err(|error| QualificationError::new(format!("MatchSet value failed: {error}")))
}

const fn selected_matcher_kind(kind: MatcherKind, index: usize) -> MatcherKind {
    match kind {
        MatcherKind::Mixed => match index % 5 {
            0 => MatcherKind::Exact,
            1 => MatcherKind::Suffix,
            2 => MatcherKind::Keyword,
            3 => MatcherKind::CidrV4,
            _ => MatcherKind::CidrV6,
        },
        other => other,
    }
}

fn generated_v4(index: usize) -> Result<Ipv4Net> {
    let index =
        u32::try_from(index).map_err(|_| QualificationError::new("IPv4 fixture index overflow"))?;
    let address = Ipv4Addr::from(0x0a00_0000_u32 | (index & 0x00ff_ffff));
    Ipv4Net::new(address, 32)
        .map_err(|_| QualificationError::new("generated IPv4 prefix is invalid"))
}

fn generated_v6(index: usize) -> Result<Ipv6Net> {
    let index = u128::try_from(index)
        .map_err(|_| QualificationError::new("IPv6 fixture index overflow"))?;
    let address = Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0000_u128 | index);
    Ipv6Net::new(address, 128)
        .map_err(|_| QualificationError::new("generated IPv6 prefix is invalid"))
}

fn match_probe_cases(kind: MatcherKind, scale: usize) -> Result<Vec<ProbeCase>> {
    let last = scale
        .checked_sub(1)
        .ok_or_else(|| QualificationError::new("MatchSet scale is zero"))?;
    let cases = match kind {
        MatcherKind::Exact => vec![
            domain_case("hit", &format!("exact-{last}.bench.invalid"), true)?,
            domain_case("miss", "exact-miss.bench.invalid", false)?,
        ],
        MatcherKind::Suffix => vec![
            domain_case("hit", &format!("child.suffix-{last}.bench.invalid"), true)?,
            domain_case("miss", "suffix-miss.example", false)?,
        ],
        MatcherKind::Keyword => vec![
            domain_case("hit", &format!("prefix-needle{last}x-suffix.invalid"), true)?,
            domain_case("miss", "keyword-miss.example", false)?,
        ],
        MatcherKind::CidrV4 => vec![
            ProbeCase {
                name: "hit",
                probe: MatchProbe::Ip(IpAddr::V4(generated_v4(last)?.addr())),
                expected: true,
            },
            ProbeCase {
                name: "miss",
                probe: MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                expected: false,
            },
        ],
        MatcherKind::CidrV6 => vec![
            ProbeCase {
                name: "hit",
                probe: MatchProbe::Ip(IpAddr::V6(generated_v6(last)?.addr())),
                expected: true,
            },
            ProbeCase {
                name: "miss",
                probe: MatchProbe::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                expected: false,
            },
        ],
        MatcherKind::Mixed => {
            let exact = last - (last % 5);
            let v4 = (0..scale).rev().find(|index| index % 5 == 3).unwrap_or(3);
            vec![
                domain_case("domain_hit", &format!("exact-{exact}.bench.invalid"), true)?,
                ProbeCase {
                    name: "ip_hit",
                    probe: MatchProbe::Ip(IpAddr::V4(generated_v4(v4)?.addr())),
                    expected: true,
                },
                domain_case("domain_miss", "mixed-miss.example", false)?,
                ProbeCase {
                    name: "ip_miss",
                    probe: MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))),
                    expected: false,
                },
            ]
        }
    };
    Ok(cases)
}

fn domain_case(name: &'static str, value: &str, expected: bool) -> Result<ProbeCase> {
    Ok(ProbeCase {
        name,
        probe: MatchProbe::Domain(
            CanonicalDomain::new(value)
                .map_err(|_| QualificationError::new("generated domain probe is invalid"))?,
        ),
        expected,
    })
}

fn probe_matches(set: &CompiledMatchSet, probe: &MatchProbe) -> bool {
    match probe {
        MatchProbe::Domain(domain) => set.matches_domain(domain),
        MatchProbe::Ip(address) => set.matches_ip(*address),
    }
}

fn run_generated_binary_srs(
    sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<Vec<FixtureEvidence>> {
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(sizes.len().saturating_mul(MatcherKind::ALL.len()))
        .map_err(|_| QualificationError::new("generated SRS evidence allocation failed"))?;
    for &scale in sizes {
        for kind in MatcherKind::ALL {
            let fixture_name = format!("generated-{}-{scale}.srs", kind.name());
            let bytes = encode_generated_srs(kind, scale)?;
            let digest = sha256_bytes(&bytes);

            let binary_region = Region::new(&GLOBAL_ALLOCATOR);
            let binary_started = Instant::now();
            let decoded = decode_srs(Cursor::new(&bytes)).map_err(|error| {
                QualificationError::new(format!(
                    "generated SRS {}/{scale} decode failed: {error}",
                    kind.name()
                ))
            })?;
            let version = decoded.version();
            let statistics = decoded.statistics();
            let capabilities = decoded.capabilities();
            let binary_set = Arc::new(decoded.compile().map_err(|error| {
                QualificationError::new(format!(
                    "generated SRS {}/{scale} compile failed: {error}",
                    kind.name()
                ))
            })?);
            let binary_build = finish_build(binary_started, &binary_region)?;

            let (synthetic_reference, _) =
                build_synthetic_srs_match_set(kind, scale, &fixture_name)?;
            let reference_set = synthetic_reference.compiled();
            let expected_statistics = generated_srs_statistics(kind, scale);
            if version != SYNTHETIC_SRS_VERSION
                || statistics != expected_statistics
                || binary_set.entry_counts().total() != scale
                || reference_set.entry_counts().total() != scale
            {
                return Err(QualificationError::new(format!(
                    "generated SRS {}/{scale} structural evidence mismatch",
                    kind.name()
                )));
            }

            // Time the two source wrappers against the exact same compiled
            // object. The independently compiled synthetic reference above
            // proves data/decoder equivalence without letting allocator layout
            // masquerade as a matcher-backend performance difference.
            let synthetic_region = Region::new(&GLOBAL_ALLOCATOR);
            let synthetic_started = Instant::now();
            let mut snapshot = RuleEngineSnapshotBuilder::new(1);
            let synthetic_match_set = snapshot
                .add_shared_match_set(Arc::clone(&binary_set))
                .map_err(|error| {
                    QualificationError::new(format!(
                        "generated synthetic SRS snapshot add failed: {error}"
                    ))
                })?;
            snapshot
                .add_rule_set(&fixture_name, synthetic_match_set)
                .map_err(|error| {
                    QualificationError::new(format!(
                        "generated synthetic SRS registration failed: {error}"
                    ))
                })?;
            let synthetic_owner = CompiledSetOwner::Snapshot {
                snapshot: snapshot.build().map_err(|error| {
                    QualificationError::new(format!(
                        "generated synthetic SRS snapshot failed: {error}"
                    ))
                })?,
                match_set: synthetic_match_set,
            };
            let synthetic_build =
                binary_build.combined(finish_build(synthetic_started, &synthetic_region)?);
            let synthetic_set = synthetic_owner.compiled();
            if !std::ptr::eq(synthetic_set, binary_set.as_ref()) {
                return Err(QualificationError::new(
                    "generated SRS timing sources do not share one compiled matcher",
                ));
            }

            for case in match_probe_cases(kind, scale)? {
                if probe_matches(reference_set, &case.probe) != case.expected
                    || probe_matches(synthetic_set, &case.probe) != case.expected
                    || probe_matches(&binary_set, &case.probe) != case.expected
                {
                    return Err(QualificationError::new(format!(
                        "generated SRS {}/{scale}/{} correctness check failed",
                        kind.name(),
                        case.name
                    )));
                }
                let scenario = format!("{}/{}", kind.name(), case.name);
                let pair_id = format!("match_set/srs/{fixture_name}/{scenario}");
                let (synthetic_result, binary_result) = benchmark_pair(
                    synthetic_set,
                    &binary_set,
                    &case.probe,
                    samples,
                    base_iterations,
                    pair_id,
                );
                measurements.push(measurement(
                    format!("match_set/synthetic_srs/{fixture_name}/{scenario}"),
                    "match_set",
                    "synthetic_srs",
                    scenario.clone(),
                    scale,
                    Some(fixture_name.clone()),
                    None,
                    base_iterations,
                    synthetic_build,
                    Some(scale),
                    synthetic_result,
                ));
                measurements.push(measurement(
                    format!("match_set/binary_srs/{fixture_name}/{scenario}"),
                    "match_set",
                    "binary_srs",
                    scenario,
                    scale,
                    Some(fixture_name.clone()),
                    None,
                    base_iterations,
                    binary_build,
                    Some(scale),
                    binary_result,
                ));
            }

            evidence.push(FixtureEvidence {
                name: fixture_name,
                provenance: "deterministic_runner_generated_canonical_srs_v2",
                bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                sha256: digest,
                srs_version: version,
                statistics: statistics.into(),
                capabilities: capabilities.into(),
            });
        }
    }
    Ok(evidence)
}

fn build_synthetic_srs_match_set(
    kind: MatcherKind,
    scale: usize,
    tag: &str,
) -> Result<(CompiledSetOwner, BuildEvidence)> {
    let region = Region::new(&GLOBAL_ALLOCATOR);
    let started = Instant::now();
    let compiled = Arc::new(compile_generated_match_set(kind, scale)?);
    let mut snapshot = RuleEngineSnapshotBuilder::new(1);
    let match_set = snapshot
        .add_shared_match_set(compiled)
        .map_err(|error| QualificationError::new(format!("snapshot add failed: {error}")))?;
    snapshot
        .add_rule_set(tag, match_set)
        .map_err(|error| QualificationError::new(format!("RuleSet add failed: {error}")))?;
    let owner = CompiledSetOwner::Snapshot {
        snapshot: snapshot
            .build()
            .map_err(|error| QualificationError::new(format!("snapshot build failed: {error}")))?,
        match_set,
    };
    let build = finish_build(started, &region)?;
    Ok((owner, build))
}

fn generated_srs_statistics(kind: MatcherKind, scale: usize) -> SrsStatistics {
    let category_count = |category| match kind {
        MatcherKind::Mixed => count_modulo_class(scale, category, 5),
        selected if selected == category => scale,
        _ => 0,
    };
    SrsStatistics {
        rules: 1,
        exact_domains: category_count(MatcherKind::Exact),
        domain_suffixes: category_count(MatcherKind::Suffix),
        domain_keywords: category_count(MatcherKind::Keyword),
        ip_cidrs: category_count(MatcherKind::CidrV4)
            .saturating_add(category_count(MatcherKind::CidrV6)),
    }
}

const fn count_modulo_class(scale: usize, category: MatcherKind, divisor: usize) -> usize {
    let remainder = match category {
        MatcherKind::Exact => 0,
        MatcherKind::Suffix => 1,
        MatcherKind::Keyword => 2,
        MatcherKind::CidrV4 => 3,
        MatcherKind::CidrV6 => 4,
        MatcherKind::Mixed => return 0,
    };
    if scale <= remainder {
        0
    } else {
        1 + (scale - 1 - remainder) / divisor
    }
}

fn encode_generated_srs(kind: MatcherKind, scale: usize) -> Result<Vec<u8>> {
    if scale == 0 {
        return Err(QualificationError::new("generated SRS scale is zero"));
    }
    let statistics = generated_srs_statistics(kind, scale);
    let mut payload = Vec::new();
    write_uvarint(1, &mut payload);
    payload.push(0);

    if statistics.exact_domains != 0 || statistics.domain_suffixes != 0 {
        payload.push(SRS_ITEM_DOMAIN);
        let mut keys = Vec::new();
        keys.try_reserve_exact(
            statistics
                .exact_domains
                .saturating_add(statistics.domain_suffixes),
        )
        .map_err(|_| QualificationError::new("generated SRS domain allocation failed"))?;
        for index in 0..scale {
            let selected = selected_matcher_kind(kind, index);
            let value = match selected {
                MatcherKind::Exact => Some(format!("exact-{index}.bench.invalid")),
                MatcherKind::Suffix => Some(format!("suffix-{index}.bench.invalid")),
                _ => None,
            };
            if let Some(value) = value {
                let mut key = Vec::new();
                key.try_reserve_exact(value.len().saturating_add(1))
                    .map_err(|_| QualificationError::new("generated SRS key allocation failed"))?;
                key.extend(value.bytes().rev());
                if selected == MatcherKind::Suffix {
                    key.push(SRS_DOMAIN_SUFFIX_MARKER);
                }
                keys.push(key);
            }
        }
        append_succinct_set(keys, &mut payload)?;
    }

    if statistics.domain_keywords != 0 {
        payload.push(SRS_ITEM_DOMAIN_KEYWORD);
        write_usize_uvarint(statistics.domain_keywords, &mut payload)?;
        for index in 0..scale {
            if selected_matcher_kind(kind, index) == MatcherKind::Keyword {
                append_byte_slice(format!("needle{index}x").as_bytes(), &mut payload)?;
            }
        }
    }

    if statistics.ip_cidrs != 0 {
        payload.push(SRS_ITEM_IP_CIDR);
        payload.push(1);
        payload.extend_from_slice(
            &u64::try_from(statistics.ip_cidrs)
                .map_err(|_| QualificationError::new("generated SRS IP count overflow"))?
                .to_be_bytes(),
        );
        for selected in [MatcherKind::CidrV4, MatcherKind::CidrV6] {
            for index in 0..scale {
                if selected_matcher_kind(kind, index) == selected {
                    let address = match selected {
                        MatcherKind::CidrV4 => IpAddr::V4(generated_v4(index)?.addr()),
                        MatcherKind::CidrV6 => IpAddr::V6(generated_v6(index)?.addr()),
                        _ => unreachable!("only IP matcher kinds are enumerated"),
                    };
                    append_ip_point(address, &mut payload);
                }
            }
        }
    }

    payload.push(SRS_ITEM_FINAL);
    payload.push(0);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&payload).map_err(|error| {
        QualificationError::new(format!("generated SRS compression failed: {error}"))
    })?;
    let compressed = encoder.finish().map_err(|error| {
        QualificationError::new(format!("generated SRS compression failed: {error}"))
    })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(4_usize.saturating_add(compressed.len()))
        .map_err(|_| QualificationError::new("generated SRS output allocation failed"))?;
    encoded.extend_from_slice(b"SRS");
    encoded.push(SYNTHETIC_SRS_VERSION);
    encoded.extend_from_slice(&compressed);
    Ok(encoded)
}

fn append_ip_point(address: IpAddr, output: &mut Vec<u8>) {
    match address {
        IpAddr::V4(address) => {
            write_uvarint(4, output);
            output.extend_from_slice(&address.octets());
            write_uvarint(4, output);
            output.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            write_uvarint(16, output);
            output.extend_from_slice(&address.octets());
            write_uvarint(16, output);
            output.extend_from_slice(&address.octets());
        }
    }
}

#[derive(Default)]
struct CanonicalTrieNode {
    first_child: Option<usize>,
    last_child: Option<usize>,
    next_sibling: Option<usize>,
    label: u8,
    terminal: bool,
}

struct CanonicalByteTrie {
    nodes: Vec<CanonicalTrieNode>,
}

impl CanonicalByteTrie {
    fn from_sorted_keys(mut keys: Vec<Vec<u8>>) -> Result<Self> {
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() || keys.iter().any(Vec::is_empty) {
            return Err(QualificationError::new(
                "generated SRS domain set contains no canonical key",
            ));
        }
        let estimated_nodes = keys
            .iter()
            .try_fold(1_usize, |total, key| total.checked_add(key.len()))
            .ok_or_else(|| QualificationError::new("generated SRS trie size overflow"))?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(estimated_nodes)
            .map_err(|_| QualificationError::new("generated SRS trie allocation failed"))?;
        nodes.push(CanonicalTrieNode::default());
        let mut previous = Vec::<u8>::new();
        let mut path = Vec::new();
        path.try_reserve_exact(
            keys.iter()
                .map(Vec::len)
                .max()
                .unwrap_or(0)
                .saturating_add(1),
        )
        .map_err(|_| QualificationError::new("generated SRS trie path allocation failed"))?;
        path.push(0);

        for key in keys {
            let common = previous
                .iter()
                .zip(&key)
                .take_while(|(left, right)| left == right)
                .count();
            path.truncate(common.saturating_add(1));
            let mut parent = *path
                .last()
                .ok_or_else(|| QualificationError::new("generated SRS trie path is empty"))?;
            for &label in &key[common..] {
                let child = nodes.len();
                nodes.push(CanonicalTrieNode {
                    label,
                    ..CanonicalTrieNode::default()
                });
                if let Some(last_child) = nodes[parent].last_child {
                    nodes[last_child].next_sibling = Some(child);
                } else {
                    nodes[parent].first_child = Some(child);
                }
                nodes[parent].last_child = Some(child);
                parent = child;
                path.push(child);
            }
            nodes[parent].terminal = true;
            previous = key;
        }
        nodes.shrink_to_fit();
        Ok(Self { nodes })
    }

    fn append_encoded(&self, output: &mut Vec<u8>) -> Result<()> {
        let mut leaves = Vec::<u64>::new();
        let mut bitmap = Vec::<u64>::new();
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(self.nodes.len().saturating_sub(1))
            .map_err(|_| QualificationError::new("generated SRS label allocation failed"))?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| QualificationError::new("generated SRS trie queue allocation failed"))?;
        queue.push_back((0_usize, 0_usize));
        let mut next_node_id = 1_usize;
        let mut bitmap_position = 0_usize;
        while let Some((node_index, node_id)) = queue.pop_front() {
            let node = self
                .nodes
                .get(node_index)
                .ok_or_else(|| QualificationError::new("generated SRS trie node is invalid"))?;
            if node.terminal {
                set_word_bit(&mut leaves, node_id)?;
            }
            let mut child = node.first_child;
            while let Some(child_index) = child {
                append_bitmap_bit(&mut bitmap, &mut bitmap_position, false)?;
                let child_node = self.nodes.get(child_index).ok_or_else(|| {
                    QualificationError::new("generated SRS trie child is invalid")
                })?;
                labels.push(child_node.label);
                queue.push_back((child_index, next_node_id));
                next_node_id = next_node_id
                    .checked_add(1)
                    .ok_or_else(|| QualificationError::new("generated SRS node ID overflow"))?;
                child = child_node.next_sibling;
            }
            append_bitmap_bit(&mut bitmap, &mut bitmap_position, true)?;
        }
        if next_node_id != self.nodes.len() {
            return Err(QualificationError::new(
                "generated SRS trie serialization lost a node",
            ));
        }
        output.push(0);
        append_u64_words(&leaves, output)?;
        append_u64_words(&bitmap, output)?;
        append_byte_slice(&labels, output)
    }
}

fn append_succinct_set(keys: Vec<Vec<u8>>, output: &mut Vec<u8>) -> Result<()> {
    CanonicalByteTrie::from_sorted_keys(keys)?.append_encoded(output)
}

fn set_word_bit(words: &mut Vec<u64>, position: usize) -> Result<()> {
    let word = position / 64;
    if words.len() <= word {
        words
            .try_reserve(word.saturating_add(1).saturating_sub(words.len()))
            .map_err(|_| QualificationError::new("generated SRS bitset allocation failed"))?;
        words.resize(word.saturating_add(1), 0);
    }
    words[word] |= 1_u64 << (position % 64);
    Ok(())
}

fn append_bitmap_bit(words: &mut Vec<u64>, position: &mut usize, value: bool) -> Result<()> {
    let current = *position;
    let word = current / 64;
    if words.len() <= word {
        words
            .try_reserve(1)
            .map_err(|_| QualificationError::new("generated SRS bitmap allocation failed"))?;
        words.push(0);
    }
    if value {
        words[word] |= 1_u64 << (current % 64);
    }
    *position = current
        .checked_add(1)
        .ok_or_else(|| QualificationError::new("generated SRS bitmap size overflow"))?;
    Ok(())
}

fn append_u64_words(words: &[u64], output: &mut Vec<u8>) -> Result<()> {
    write_usize_uvarint(words.len(), output)?;
    for word in words {
        output.extend_from_slice(&word.to_be_bytes());
    }
    Ok(())
}

fn append_byte_slice(bytes: &[u8], output: &mut Vec<u8>) -> Result<()> {
    write_usize_uvarint(bytes.len(), output)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_usize_uvarint(value: usize, output: &mut Vec<u8>) -> Result<()> {
    write_uvarint(
        u64::try_from(value)
            .map_err(|_| QualificationError::new("generated SRS length overflow"))?,
        output,
    );
    Ok(())
}

fn write_uvarint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn run_real_srs(
    workspace_root: &Path,
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<Vec<FixtureEvidence>> {
    let fixtures = [
        (
            "ads.srs",
            MatchProbe::Domain(canonical("x.0.myikas.com")?),
            MatchProbe::Domain(canonical("not-an-ad-fixture-match.invalid")?),
        ),
        (
            "ai.srs",
            MatchProbe::Domain(canonical("api.openai.example")?),
            MatchProbe::Domain(canonical("not-an-ai-fixture-match.invalid")?),
        ),
        (
            "cn.srs",
            MatchProbe::Domain(canonical("x.0.zone")?),
            MatchProbe::Domain(canonical("not-a-cn-fixture-match.invalid")?),
        ),
        (
            "cnip.srs",
            MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 8, 8))),
            MatchProbe::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ),
    ];
    let mut evidence = Vec::new();
    for (name, hit, miss) in fixtures {
        let path = workspace_root.join("tests/fixtures/srs").join(name);
        let bytes = fs::read(&path).map_err(|error| {
            QualificationError::new(format!("SRS fixture {name} could not be read: {error}"))
        })?;
        let digest = sha256_bytes(&bytes);
        let binary_region = Region::new(&GLOBAL_ALLOCATOR);
        let binary_started = Instant::now();
        let decoded = decode_srs(Cursor::new(&bytes)).map_err(|error| {
            QualificationError::new(format!("SRS fixture {name} decode failed: {error}"))
        })?;
        let version = decoded.version();
        let statistics = decoded.statistics();
        let capabilities = decoded.capabilities();
        let binary_set = Arc::new(decoded.compile().map_err(|error| {
            QualificationError::new(format!("SRS fixture {name} compile failed: {error}"))
        })?);
        let binary_build = finish_build(binary_started, &binary_region)?;

        let synthetic_region = Region::new(&GLOBAL_ALLOCATOR);
        let synthetic_started = Instant::now();
        let mut snapshot = RuleEngineSnapshotBuilder::new(1);
        let synthetic_match_set = snapshot
            .add_shared_match_set(Arc::clone(&binary_set))
            .map_err(|error| {
                QualificationError::new(format!("synthetic SRS snapshot add failed: {error}"))
            })?;
        snapshot
            .add_rule_set(name, synthetic_match_set)
            .map_err(|error| {
                QualificationError::new(format!("synthetic SRS registration failed: {error}"))
            })?;
        let synthetic_owner = CompiledSetOwner::Snapshot {
            snapshot: snapshot.build().map_err(|error| {
                QualificationError::new(format!("synthetic SRS snapshot failed: {error}"))
            })?,
            match_set: synthetic_match_set,
        };
        let synthetic_build =
            binary_build.combined(finish_build(synthetic_started, &synthetic_region)?);

        let synthetic_set = synthetic_owner.compiled();
        let scale = binary_set.entry_counts().total();
        let capability_name = capability_name(capabilities);
        for (case, probe, expected) in [("hit", &hit, true), ("miss", &miss, false)] {
            if probe_matches(&binary_set, probe) != expected
                || probe_matches(synthetic_set, probe) != expected
            {
                return Err(QualificationError::new(format!(
                    "SRS fixture {name} {case} probe failed"
                )));
            }
            let scenario = format!("{capability_name}/{case}");
            let (synthetic_result, binary_result) = benchmark_pair(
                synthetic_set,
                &binary_set,
                probe,
                samples,
                base_iterations,
                format!("match_set/srs/{name}/{scenario}"),
            );
            measurements.push(measurement(
                format!("match_set/synthetic_srs/{name}/{scenario}"),
                "match_set",
                "synthetic_srs",
                scenario.clone(),
                scale,
                Some(name.to_owned()),
                None,
                base_iterations,
                synthetic_build,
                Some(scale),
                synthetic_result,
            ));
            measurements.push(measurement(
                format!("match_set/binary_srs/{name}/{scenario}"),
                "match_set",
                "binary_srs",
                scenario,
                scale,
                Some(name.to_owned()),
                None,
                base_iterations,
                binary_build,
                Some(scale),
                binary_result,
            ));
        }
        evidence.push(FixtureEvidence {
            name: name.to_owned(),
            provenance: "pinned_repository_fixture",
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256: digest,
            srs_version: version,
            statistics: statistics.into(),
            capabilities: capabilities.into(),
        });
    }
    Ok(evidence)
}

fn canonical(value: &str) -> Result<CanonicalDomain> {
    CanonicalDomain::new(value)
        .map_err(|_| QualificationError::new("qualification domain is invalid"))
}

fn capability_name(capabilities: MatchSetCapabilities) -> &'static str {
    let count = [
        capabilities.exact_domain,
        capabilities.domain_suffix,
        capabilities.domain_keyword,
        capabilities.ip_cidr,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if count > 1 {
        "mixed"
    } else if capabilities.exact_domain {
        "exact"
    } else if capabilities.domain_suffix {
        "suffix"
    } else if capabilities.domain_keyword {
        "keyword"
    } else if capabilities.ip_cidr {
        "cidr"
    } else {
        "empty"
    }
}

#[derive(Clone, Copy)]
enum RouteSource {
    Ordinary,
    RuleSet,
    Mixed,
}

struct RouteFixture {
    program: OrderedRouteProgram<(), usize>,
    snapshot: Option<Arc<RuleEngineSnapshot>>,
    build: BuildEvidence,
}

fn run_route_programs(
    sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in sizes {
        let ordinary = build_route_fixture(count, RouteSource::Ordinary)?;
        let ruleset = build_route_fixture(count, RouteSource::RuleSet)?;
        let mixed = build_route_fixture(count, RouteSource::Mixed)?;
        let expected_mode = if count <= 64 {
            RuleProgramMode::SmallLinear
        } else {
            RuleProgramMode::Indexed
        };
        if [
            ordinary.program.mode(),
            ruleset.program.mode(),
            mixed.program.mode(),
        ]
        .into_iter()
        .any(|mode| mode != expected_mode)
        {
            return Err(QualificationError::new(
                "route program selected an unexpected execution mode",
            ));
        }
        let iterations = scaled_iterations(base_iterations, 1, count);
        let mut ordinary_scratch = ordinary.program.evaluation_scratch().map_err(|error| {
            QualificationError::new(format!("ordinary route scratch failed: {error}"))
        })?;
        let mut ruleset_scratch = ruleset.program.evaluation_scratch().map_err(|error| {
            QualificationError::new(format!("RuleSet route scratch failed: {error}"))
        })?;
        let mut mixed_scratch = mixed.program.evaluation_scratch().map_err(|error| {
            QualificationError::new(format!("mixed route scratch failed: {error}"))
        })?;
        let reserved = [
            ordinary_scratch.reserved_words(),
            ruleset_scratch.reserved_words(),
            mixed_scratch.reserved_words(),
        ];
        for (case, position) in [
            ("first", Some(0_usize)),
            ("middle", Some(count / 2)),
            ("last", Some(count - 1)),
            ("miss", None),
        ] {
            let index = position.unwrap_or(count);
            let target = TargetAddr::domain(&format!("route-{index}.bench.invalid"), 443)
                .map_err(|_| QualificationError::new("route target is invalid"))?;
            let expected = position.unwrap_or(usize::MAX);
            for (source, fixture, scratch) in [
                ("ordinary_only", &ordinary, &mut ordinary_scratch),
                ("ruleset_only", &ruleset, &mut ruleset_scratch),
                ("mixed", &mixed, &mut mixed_scratch),
            ] {
                let actual = evaluate_route(
                    &fixture.program,
                    fixture.snapshot.as_ref(),
                    &target,
                    index,
                    scratch,
                );
                if actual != expected {
                    return Err(QualificationError::new(format!(
                        "route {source}/{count}/{case} returned {actual}, expected {expected}"
                    )));
                }
            }

            let scenario = format!(
                "{}/{case}",
                match expected_mode {
                    RuleProgramMode::SmallLinear => "small_linear",
                    RuleProgramMode::Indexed => "indexed",
                }
            );
            let (ordinary_result, ruleset_result) = benchmark_operation_pair(
                || {
                    evaluate_route(
                        &ordinary.program,
                        ordinary.snapshot.as_ref(),
                        &target,
                        index,
                        &mut ordinary_scratch,
                    ) as u64
                },
                || {
                    evaluate_route(
                        &ruleset.program,
                        ruleset.snapshot.as_ref(),
                        &target,
                        index,
                        &mut ruleset_scratch,
                    ) as u64
                },
                samples,
                iterations,
                format!("route_program/{count}/{scenario}"),
            );
            let mixed_result = benchmark(
                || {
                    evaluate_route(
                        &mixed.program,
                        mixed.snapshot.as_ref(),
                        &target,
                        index,
                        &mut mixed_scratch,
                    ) as u64
                },
                samples,
                iterations,
            );
            for (source, build, result) in [
                ("ordinary_only", ordinary.build, ordinary_result),
                ("ruleset_only", ruleset.build, ruleset_result),
                ("mixed", mixed.build, mixed_result),
            ] {
                measurements.push(measurement(
                    format!("route_program/{source}/{count}/{scenario}"),
                    "route_program",
                    source,
                    scenario.clone(),
                    count,
                    None,
                    Some(expected_mode),
                    iterations,
                    build,
                    Some(count),
                    result,
                ));
            }
        }
        // Production enables category observation for every Route evaluation.
        // Exercise that selected-rule recheck at qualification-only scales so
        // the pre-matrix smoke scenario set remains compatible with the pinned
        // parent runner used by alternating A/A and A/B control runs.
        if count >= 1_000 {
            for (case, index) in [("first_observed", 0_usize), ("last_observed", count - 1)] {
                let target = TargetAddr::domain(&format!("route-{index}.bench.invalid"), 443)
                    .map_err(|_| QualificationError::new("observed route target is invalid"))?;
                let actual = evaluate_route_observed(
                    &mixed.program,
                    mixed.snapshot.as_ref(),
                    &target,
                    index,
                    &mut mixed_scratch,
                );
                if actual.selected != index {
                    return Err(QualificationError::new(format!(
                        "observed route {count}/{case} returned {}, expected {index}",
                        actual.selected
                    )));
                }
                let scenario = format!("indexed/{case}");
                let result = benchmark(
                    || {
                        evaluate_route_observed(
                            &mixed.program,
                            mixed.snapshot.as_ref(),
                            &target,
                            index,
                            &mut mixed_scratch,
                        )
                        .checksum()
                    },
                    samples,
                    iterations,
                );
                measurements.push(measurement(
                    format!("route_program/mixed_observed/{count}/{scenario}"),
                    "route_program",
                    "mixed_observed",
                    scenario,
                    count,
                    None,
                    Some(expected_mode),
                    iterations,
                    mixed.build,
                    Some(count),
                    result,
                ));
            }
        }
        if ordinary_scratch.reserved_words() != reserved[0]
            || ruleset_scratch.reserved_words() != reserved[1]
            || mixed_scratch.reserved_words() != reserved[2]
        {
            return Err(QualificationError::new(
                "route evaluation scratch grew on the measured path",
            ));
        }
    }
    Ok(())
}

fn build_route_fixture(count: usize, source: RouteSource) -> Result<RouteFixture> {
    let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
    let started = Instant::now();
    let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(count)
        .map_err(|_| QualificationError::new("route fixture allocation failed"))?;
    for index in 0..count {
        let mut fields = Vec::new();
        if matches!(source, RouteSource::Ordinary | RouteSource::Mixed) {
            fields.push(RouteMatchField::Domain(vec![
                DomainName::new(&format!("route-{index}.bench.invalid")).map_err(|_| {
                    QualificationError::new("route ordinary domain value is invalid")
                })?,
            ]));
        }
        if matches!(source, RouteSource::RuleSet | RouteSource::Mixed) {
            let mut builder = MatchSetBuilder::new();
            builder
                .add_exact_domain(&format!("route-{index}.bench.invalid"))
                .map_err(|error| {
                    QualificationError::new(format!("route MatchSet value failed: {error}"))
                })?;
            let match_set = snapshot_builder
                .add_match_set(builder.build().map_err(|error| {
                    QualificationError::new(format!("route MatchSet build failed: {error}"))
                })?)
                .map_err(|error| {
                    QualificationError::new(format!("route snapshot add failed: {error}"))
                })?;
            let rule_set = snapshot_builder
                .add_rule_set(&format!("route-{index}"), match_set)
                .map_err(|error| {
                    QualificationError::new(format!("route RuleSet add failed: {error}"))
                })?;
            fields.push(RouteMatchField::RuleSet(vec![rule_set]));
        }
        let matcher = RouteMatcher::try_new(fields).map_err(|error| {
            QualificationError::new(format!("route matcher build failed: {error}"))
        })?;
        rules.push(OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(index),
        ));
    }
    let program = OrderedRouteProgram::try_new(rules, usize::MAX)
        .map_err(|error| QualificationError::new(format!("route program build failed: {error}")))?;
    let snapshot = if matches!(source, RouteSource::Ordinary) {
        None
    } else {
        Some(Arc::new(snapshot_builder.build().map_err(|error| {
            QualificationError::new(format!("route snapshot build failed: {error}"))
        })?))
    };
    let build = finish_build(started, &allocation_region)?;
    Ok(RouteFixture {
        program,
        snapshot,
        build,
    })
}

fn evaluate_route(
    program: &OrderedRouteProgram<(), usize>,
    snapshot: Option<&Arc<RuleEngineSnapshot>>,
    target: &TargetAddr,
    inbound: usize,
    scratch: &mut ferrum2_rule::RuleEvaluationScratch,
) -> usize {
    let action = match snapshot {
        Some(snapshot) => {
            let mut evaluation = program.evaluate_with_snapshot_and_scratch(
                inbound,
                Network::Tcp,
                target,
                Arc::clone(snapshot),
                scratch,
            );
            evaluation.next(RouteMetadata::new(None, None))
        }
        None => {
            let mut evaluation =
                program.evaluate_with_scratch(inbound, Network::Tcp, target, scratch);
            evaluation.next(RouteMetadata::new(None, None))
        }
    };
    match action {
        Some(RouteProgramAction::Terminal(value)) | Some(RouteProgramAction::Final(value)) => {
            *value
        }
        Some(RouteProgramAction::Continue(_)) | None => usize::MAX - 1,
    }
}

#[derive(Clone, Copy)]
struct ObservedRouteOutcome {
    selected: usize,
    telemetry: u64,
}

impl ObservedRouteOutcome {
    fn checksum(self) -> u64 {
        u64::try_from(self.selected)
            .unwrap_or(u64::MAX)
            .wrapping_mul(4_099)
            ^ self.telemetry
    }
}

fn evaluate_route_observed(
    program: &OrderedRouteProgram<(), usize>,
    snapshot: Option<&Arc<RuleEngineSnapshot>>,
    target: &TargetAddr,
    inbound: usize,
    scratch: &mut ferrum2_rule::RuleEvaluationScratch,
) -> ObservedRouteOutcome {
    match snapshot {
        Some(snapshot) => {
            let mut evaluation = program.evaluate_with_snapshot_and_scratch(
                inbound,
                Network::Tcp,
                target,
                Arc::clone(snapshot),
                scratch,
            );
            evaluation.enable_match_observation();
            let action = evaluation.next(RouteMetadata::new(None, None));
            finish_observed_route(action, evaluation.last_match_observation())
        }
        None => {
            let mut evaluation =
                program.evaluate_with_scratch(inbound, Network::Tcp, target, scratch);
            evaluation.enable_match_observation();
            let action = evaluation.next(RouteMetadata::new(None, None));
            finish_observed_route(action, evaluation.last_match_observation())
        }
    }
}

fn finish_observed_route(
    action: Option<RouteProgramAction<'_, usize>>,
    observation: RouteMatchObservation,
) -> ObservedRouteOutcome {
    let mut telemetry = 0_u64;
    for source in RouteMatchSource::ALL {
        for r#type in RouteMatchType::ALL {
            telemetry = telemetry.rotate_left(3)
                ^ u64::from(observation.evaluated(source, r#type))
                ^ (u64::from(observation.matched(source, r#type)) << 1);
        }
    }
    let selected = match action {
        Some(RouteProgramAction::Terminal(value)) | Some(RouteProgramAction::Final(value)) => {
            *value
        }
        Some(RouteProgramAction::Continue(_)) | None => usize::MAX - 1,
    };
    ObservedRouteOutcome {
        selected,
        telemetry,
    }
}

fn scaled_iterations(base: u64, numerator: usize, scale: usize) -> u64 {
    let numerator = u64::try_from(numerator).unwrap_or(u64::MAX);
    let scale = u64::try_from(scale).unwrap_or(u64::MAX);
    base.saturating_mul(numerator)
        .checked_div(scale)
        .unwrap_or(1)
        .max(1)
}

#[derive(Clone, Copy)]
enum DnsQuerySource {
    Ordinary,
    RuleSet,
}

#[cfg(test)]
impl DnsQuerySource {
    const ALL: [Self; 2] = [Self::Ordinary, Self::RuleSet];
}

struct DnsQnameFixture {
    program: DnsPolicyProgram,
    snapshot: Arc<RuleEngineSnapshot>,
    build: BuildEvidence,
}

fn run_dns_policy(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    run_dns_qname(rule_sizes, samples, base_iterations, measurements)?;
    // Response continuation deliberately visits each response-dependent row.
    // Keep those scenarios bounded while qname indexing carries the 10k scale.
    let response_sizes = rule_sizes
        .iter()
        .copied()
        .filter(|count| matches!(*count, 1 | 100 | 1_000))
        .collect::<Vec<_>>();
    run_dns_cnip(&response_sizes, samples, base_iterations, measurements)?;
    run_dns_cache(&response_sizes, samples, base_iterations, measurements)?;
    run_dns_continuation(&response_sizes, samples, base_iterations, measurements)
}

fn run_dns_qname(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in rule_sizes {
        let ordinary = build_dns_qname_fixture(count, DnsQuerySource::Ordinary)?;
        let ruleset = build_dns_qname_fixture(count, DnsQuerySource::RuleSet)?;
        let iterations = scaled_iterations(base_iterations, 1, count);
        for (case, position) in [
            ("first_hit", Some(0_usize)),
            ("last_hit", Some(count - 1)),
            ("miss", None),
        ] {
            let index = position.unwrap_or(count);
            let name = Name::from_str(&format!("dns-{index}.bench.invalid."))
                .map_err(|_| QualificationError::new("DNS qualification name is invalid"))?;
            let expected = position
                .and_then(|position| u32::try_from(position).ok())
                .unwrap_or(u32::MAX);
            let (ordinary_actual, ordinary_visits) = evaluate_dns_qname_evidence(&ordinary, &name);
            let (ruleset_actual, ruleset_visits) = evaluate_dns_qname_evidence(&ruleset, &name);
            if ordinary_actual != expected || ruleset_actual != expected {
                return Err(QualificationError::new(format!(
                    "DNS qname parity {count}/{case} returned ordinary={ordinary_actual}, RuleSet={ruleset_actual}, expected={expected}"
                )));
            }
            if ordinary.program.mode() == RuleProgramMode::Indexed
                && (ordinary_visits >= count || ruleset_visits >= count)
            {
                return Err(QualificationError::new(format!(
                    "DNS indexed qname {count}/{case} was not sublinear: ordinary={ordinary_visits}, RuleSet={ruleset_visits}"
                )));
            }
            let scenario = format!("qname_{case}");
            let (ordinary_result, ruleset_result) = benchmark_operation_pair(
                || u64::from(evaluate_dns_qname(&ordinary, &name)),
                || u64::from(evaluate_dns_qname(&ruleset, &name)),
                samples,
                iterations,
                format!("dns_policy/{count}/{scenario}"),
            );
            for (source, fixture, visits, result) in [
                (
                    "ordinary_inline",
                    &ordinary,
                    ordinary_visits,
                    ordinary_result,
                ),
                ("ruleset", &ruleset, ruleset_visits, ruleset_result),
            ] {
                let mut row = measurement(
                    format!("dns_policy/{source}/{count}/{scenario}"),
                    "dns_policy",
                    source,
                    scenario.clone(),
                    count,
                    None,
                    Some(fixture.program.mode()),
                    iterations,
                    fixture.build,
                    Some(count),
                    result,
                );
                row.query_candidate_visits = Some(visits);
                measurements.push(row);
            }
        }
    }
    Ok(())
}

fn build_dns_qname_fixture(count: usize, source: DnsQuerySource) -> Result<DnsQnameFixture> {
    let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
    let started = Instant::now();
    let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(count)
        .map_err(|_| QualificationError::new("DNS policy fixture allocation failed"))?;
    for index in 0..count {
        let mut builder = MatchSetBuilder::new();
        builder
            .add_exact_domain(&format!("dns-{index}.bench.invalid"))
            .map_err(|error| QualificationError::new(format!("DNS qname value failed: {error}")))?;
        let set = builder.build().map_err(|error| {
            QualificationError::new(format!("DNS qname MatchSet failed: {error}"))
        })?;
        let matcher = match source {
            DnsQuerySource::Ordinary => DnsPolicyMatcher::try_new(
                vec![Arc::new(set)],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            DnsQuerySource::RuleSet => {
                let match_set = snapshot_builder.add_match_set(set).map_err(|error| {
                    QualificationError::new(format!("DNS snapshot add failed: {error}"))
                })?;
                let rule_set = snapshot_builder
                    .add_rule_set(&format!("dns-{index}"), match_set)
                    .map_err(|error| {
                        QualificationError::new(format!("DNS RuleSet add failed: {error}"))
                    })?;
                DnsPolicyMatcher::try_new(
                    Vec::new(),
                    vec![rule_set],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            }
        }
        .map_err(|error| QualificationError::new(format!("DNS matcher build failed: {error}")))?;
        let server = DnsServerId::new(
            u32::try_from(index).map_err(|_| QualificationError::new("DNS server id overflow"))?,
        );
        rules.push(DnsPolicyRule::new(
            matcher,
            DnsPolicyAction::Route(DnsPolicyRoute::new(server, DnsStrategy::PreferIpv4)),
        ));
    }
    let snapshot =
        Arc::new(snapshot_builder.build().map_err(|error| {
            QualificationError::new(format!("DNS snapshot build failed: {error}"))
        })?);
    let final_route = DnsPolicyRoute::new(DnsServerId::new(u32::MAX), DnsStrategy::PreferIpv4);
    let program = DnsPolicyProgram::try_new(rules, final_route, &snapshot)
        .map_err(|error| QualificationError::new(format!("DNS policy build failed: {error}")))?;
    let build = finish_build(started, &allocation_region)?;
    Ok(DnsQnameFixture {
        program,
        snapshot,
        build,
    })
}

fn evaluate_dns_qname(fixture: &DnsQnameFixture, name: &Name) -> u32 {
    evaluate_dns_qname_evidence(fixture, name).0
}

fn evaluate_dns_qname_evidence(fixture: &DnsQnameFixture, name: &Name) -> (u32, usize) {
    let query = DnsPolicyQuery::new(0, Network::Udp, name.clone(), RecordType::A);
    let mut scratch = fixture.program.evaluation_scratch();
    let mut evaluation = fixture.program.evaluate_with_snapshot_and_scratch(
        query,
        Arc::clone(&fixture.snapshot),
        &mut scratch,
    );
    let selected = match evaluation.next_step() {
        Ok(Some(step)) => step
            .route()
            .map(|route| route.server().get())
            .unwrap_or(u32::MAX - 1),
        Ok(None) | Err(_) => u32::MAX - 2,
    };
    (selected, evaluation.observation().query_candidates())
}

fn run_dns_cnip(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in rule_sizes {
        let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
        let started = Instant::now();
        let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
        let mut rules = Vec::new();
        rules
            .try_reserve_exact(count)
            .map_err(|_| QualificationError::new("cnip rule allocation failed"))?;
        let local = DnsPolicyRoute::new(DnsServerId::new(7), DnsStrategy::Ipv4Only);
        let final_route = DnsPolicyRoute::new(DnsServerId::new(8), DnsStrategy::PreferIpv4);
        for index in 0..count {
            let mut builder = MatchSetBuilder::new();
            builder
                .add_ip(IpAddr::V4(dns_bench_ip(index)))
                .map_err(|error| QualificationError::new(format!("cnip value failed: {error}")))?;
            let match_set = snapshot_builder
                .add_match_set(builder.build().map_err(|error| {
                    QualificationError::new(format!("cnip MatchSet failed: {error}"))
                })?)
                .map_err(|error| {
                    QualificationError::new(format!("cnip snapshot add failed: {error}"))
                })?;
            let rule_set = snapshot_builder
                .add_rule_set(&format!("cnip-{index}"), match_set)
                .map_err(|error| {
                    QualificationError::new(format!("cnip RuleSet add failed: {error}"))
                })?;
            let matcher = DnsPolicyMatcher::try_new(
                Vec::new(),
                vec![rule_set],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .map_err(|error| QualificationError::new(format!("cnip matcher failed: {error}")))?;
            rules.push(DnsPolicyRule::new(matcher, DnsPolicyAction::Route(local)));
        }
        let snapshot =
            Arc::new(snapshot_builder.build().map_err(|error| {
                QualificationError::new(format!("cnip snapshot failed: {error}"))
            })?);
        let program = DnsPolicyProgram::try_new(rules, final_route, &snapshot)
            .map_err(|error| QualificationError::new(format!("cnip program failed: {error}")))?;
        let name = Name::from_str("service.bench.invalid.")
            .map_err(|_| QualificationError::new("cnip qname is invalid"))?;
        let build = finish_build(started, &allocation_region)?;
        let fixture = DnsResponseFixture {
            program,
            snapshot,
            name,
            build,
        };
        let hit = dns_a_response("service.bench.invalid.", dns_bench_ip(count - 1))?;
        let miss = dns_a_response("service.bench.invalid.", Ipv4Addr::new(203, 0, 113, 3))?;
        let iterations = scaled_iterations(base_iterations, 1, count);
        for (case, response, expected) in [
            ("cnip_response_hit", &hit, local.server().get()),
            ("cnip_response_miss", &miss, final_route.server().get()),
        ] {
            let actual = evaluate_dns_response(&fixture, response);
            if actual != expected {
                return Err(QualificationError::new(format!(
                    "DNS {case}/{count} returned {actual}, expected {expected}"
                )));
            }
            let result = benchmark(
                || u64::from(evaluate_dns_response(&fixture, response)),
                samples,
                iterations,
            );
            measurements.push(measurement(
                format!("dns_policy/ruleset/{count}/{case}"),
                "dns_policy",
                "ruleset",
                case,
                count,
                None,
                Some(fixture.program.mode()),
                iterations,
                fixture.build,
                Some(count),
                result,
            ));
        }
    }
    Ok(())
}

fn dns_bench_ip(index: usize) -> Ipv4Addr {
    let value = u32::try_from(index).unwrap_or(u32::MAX);
    Ipv4Addr::new(
        10,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    )
}

struct DnsResponseFixture {
    program: DnsPolicyProgram,
    snapshot: Arc<RuleEngineSnapshot>,
    name: Name,
    build: BuildEvidence,
}

fn evaluate_dns_response(fixture: &DnsResponseFixture, response: &Message) -> u32 {
    let query = DnsPolicyQuery::new(0, Network::Udp, fixture.name.clone(), RecordType::A);
    let mut evaluation = fixture
        .program
        .evaluate_with_snapshot(query, Arc::clone(&fixture.snapshot));
    let mut step = match evaluation.next_step() {
        Ok(Some(step)) => step,
        Ok(None) | Err(_) => return u32::MAX - 2,
    };
    loop {
        match step {
            DnsPolicyStep::EvaluateResponse { .. } => {
                step = match evaluation.evaluate_response(response) {
                    Ok(step) => step,
                    Err(_) => return u32::MAX - 2,
                };
            }
            terminal => {
                return terminal
                    .route()
                    .map(|route| route.server().get())
                    .unwrap_or(u32::MAX - 1);
            }
        }
    }
}

fn dns_a_response(owner: &str, address: Ipv4Addr) -> Result<Message> {
    let mut response = Message::new(1, MessageType::Response, OpCode::Query);
    response.add_answer(Record::from_rdata(
        Name::from_str(owner)
            .map_err(|_| QualificationError::new("DNS response owner is invalid"))?,
        60,
        RData::A(A(address)),
    ));
    Ok(response)
}

fn run_dns_cache(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in rule_sizes {
        let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
        let started = Instant::now();
        let capacity = NonZeroUsize::new(count.saturating_add(1))
            .ok_or_else(|| QualificationError::new("DNS cache capacity overflow"))?;
        let cache = DnsCache::try_new(capacity)
            .map_err(|error| QualificationError::new(format!("DNS cache build failed: {error}")))?;
        let now = Instant::now();
        let mut hit_key = None;
        for index in 0..count {
            let key = DnsCacheKey::new(
                DnsServerId::new(3),
                canonical(&format!("cache-{index}.bench.invalid"))?,
                DnsCacheQtype::A,
                ResolverGeneration::new(1),
            );
            cache
                .insert_positive(
                    key.clone(),
                    DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, 9)])),
                    Duration::from_secs(60),
                    now,
                )
                .map_err(|error| {
                    QualificationError::new(format!("DNS cache insert failed: {error}"))
                })?;
            hit_key = Some(key);
        }
        let hit_key = hit_key.ok_or_else(|| QualificationError::new("empty DNS cache scale"))?;
        let miss_key = DnsCacheKey::new(
            DnsServerId::new(3),
            canonical("cache-miss.bench.invalid")?,
            DnsCacheQtype::A,
            ResolverGeneration::new(1),
        );
        let build = finish_build(started, &allocation_region)?;
        for (case, key, expected) in [
            ("cache_hit", &hit_key, 1_u64),
            ("cache_miss", &miss_key, 0_u64),
        ] {
            let read_cache = || match cache.get(key, now) {
                Ok(Some(DnsCacheAnswer::Positive(_))) => 1,
                Ok(Some(DnsCacheAnswer::Negative)) => 2,
                Ok(None) => 0,
                Err(_) => u64::MAX,
            };
            if read_cache() != expected {
                return Err(QualificationError::new(format!(
                    "DNS {case}/{count} correctness check failed"
                )));
            }
            let result = benchmark(read_cache, samples, base_iterations);
            measurements.push(measurement(
                format!("dns_policy/cache/{count}/{case}"),
                "dns_policy",
                "cache",
                case,
                count,
                None,
                None,
                base_iterations,
                build,
                Some(count),
                result,
            ));
        }
    }
    Ok(())
}

fn run_dns_continuation(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &continuations in rule_sizes {
        let rule_count = continuations.max(2);
        let allocation_region = Region::new(&GLOBAL_ALLOCATOR);
        let started = Instant::now();
        let mut snapshot_builder = RuleEngineSnapshotBuilder::new(1);
        let mut ids = Vec::new();
        ids.try_reserve_exact(rule_count)
            .map_err(|_| QualificationError::new("continuation id allocation failed"))?;
        for index in 0..rule_count {
            let mut builder = MatchSetBuilder::new();
            builder
                .add_ip(IpAddr::V4(dns_bench_ip(index.saturating_add(10_000))))
                .map_err(|error| {
                    QualificationError::new(format!("continuation IP failed: {error}"))
                })?;
            let match_set = snapshot_builder
                .add_match_set(builder.build().map_err(|error| {
                    QualificationError::new(format!("continuation MatchSet failed: {error}"))
                })?)
                .map_err(|error| {
                    QualificationError::new(format!("continuation snapshot add failed: {error}"))
                })?;
            ids.push(
                snapshot_builder
                    .add_rule_set(&format!("continuation-{index}"), match_set)
                    .map_err(|error| {
                        QualificationError::new(format!("continuation RuleSet add failed: {error}"))
                    })?,
            );
        }
        let local = DnsPolicyRoute::new(DnsServerId::new(11), DnsStrategy::Ipv4Only);
        let final_route = DnsPolicyRoute::new(DnsServerId::new(12), DnsStrategy::PreferIpv4);
        let mut rules = Vec::new();
        rules
            .try_reserve_exact(rule_count)
            .map_err(|_| QualificationError::new("continuation rule allocation failed"))?;
        for id in ids {
            let matcher =
                DnsPolicyMatcher::try_new(Vec::new(), vec![id], Vec::new(), Vec::new(), Vec::new())
                    .map_err(|error| {
                        QualificationError::new(format!("continuation matcher failed: {error}"))
                    })?;
            rules.push(DnsPolicyRule::new(matcher, DnsPolicyAction::Route(local)));
        }
        let snapshot = Arc::new(snapshot_builder.build().map_err(|error| {
            QualificationError::new(format!("continuation snapshot failed: {error}"))
        })?);
        let program =
            DnsPolicyProgram::try_new(rules, final_route, &snapshot).map_err(|error| {
                QualificationError::new(format!("continuation program failed: {error}"))
            })?;
        let name = Name::from_str("continuation.bench.invalid.")
            .map_err(|_| QualificationError::new("continuation qname is invalid"))?;
        let build = finish_build(started, &allocation_region)?;
        let fixture = DnsResponseFixture {
            program,
            snapshot,
            name,
            build,
        };
        let response = dns_a_response(
            "continuation.bench.invalid.",
            dns_bench_ip(rule_count.saturating_sub(1).saturating_add(10_000)),
        )?;
        let evaluate = || evaluate_dns_response(&fixture, &response);
        if evaluate() != local.server().get() {
            return Err(QualificationError::new(format!(
                "DNS continuation/{continuations} correctness check failed"
            )));
        }
        let iterations = scaled_iterations(base_iterations, 1, rule_count);
        let result = benchmark(|| u64::from(evaluate()), samples, iterations);
        measurements.push(measurement(
            format!("dns_policy/ruleset/{continuations}/same_server_continuation"),
            "dns_policy",
            "ruleset",
            "same_server_continuation",
            continuations,
            None,
            Some(fixture.program.mode()),
            iterations,
            fixture.build,
            Some(rule_count),
            result,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static ALLOCATOR_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn allocator_test_lock() -> MutexGuard<'static, ()> {
        ALLOCATOR_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn profiles_are_bounded_and_one_hundred_thousand_is_opt_in() {
        let _guard = allocator_test_lock();
        assert_eq!(Profile::Smoke.match_sizes(), vec![100]);
        assert_eq!(
            Profile::Qualification.match_sizes(),
            vec![100, 1_000, 10_000]
        );
        assert!(!Profile::Qualification.match_sizes().contains(&100_000));
        assert_eq!(
            Profile::Qualification.route_sizes(),
            vec![1, 32, 64, 1_000, 10_000]
        );
        assert_eq!(Profile::Smoke.dns_rule_sizes(), vec![1]);
        assert_eq!(
            Profile::Qualification.dns_rule_sizes(),
            vec![1, 64, 65, 100, 1_000, 10_000]
        );
        assert_eq!(Profile::Smoke.default_samples(), 101);
        assert_eq!(Profile::Qualification.default_samples(), 101);
        assert!(!Profile::Smoke.includes_generated_binary_srs());
        assert!(Profile::Qualification.includes_generated_binary_srs());
    }

    #[test]
    fn nearest_rank_retains_observed_values() {
        let _guard = allocator_test_lock();
        let values = [8.0, 2.0, 5.0, 1.0, 9.0];
        assert_eq!(nearest_rank(&values, 50), 5.0);
        assert_eq!(nearest_rank(&values, 99), 9.0);
    }

    #[test]
    fn ordinary_and_synthetic_sources_use_equivalent_compiled_matchers() {
        let _guard = allocator_test_lock();
        for synthetic in [false, true] {
            let (owner, build) = build_generated_match_set(MatcherKind::Mixed, 100, synthetic)
                .expect("generated MatchSet");
            assert!(build.allocations > 0);
            assert!(build.net_retained_bytes > 0);
            let cases = match_probe_cases(MatcherKind::Mixed, 100).expect("probes");
            for case in cases {
                assert_eq!(probe_matches(owner.compiled(), &case.probe), case.expected);
                let measured = benchmark(
                    || u64::from(probe_matches(owner.compiled(), &case.probe)),
                    5,
                    32,
                );
                assert_eq!(measured.samples.len(), 5);
                assert_eq!(measured.allocation_samples.len(), 5);
                assert!(
                    measured
                        .sample_batch_nanoseconds
                        .iter()
                        .all(|elapsed| *elapsed >= MIN_SAMPLE_WINDOW_NANOSECONDS)
                );
                assert!(
                    measured
                        .allocation_samples
                        .iter()
                        .all(|sample| sample.iterations == 1)
                );
            }
        }
    }

    #[test]
    fn generated_binary_srs_matrix_is_deterministic_and_strictly_decoded() {
        let _guard = allocator_test_lock();
        let scale = 25;
        for kind in MatcherKind::ALL {
            let first = encode_generated_srs(kind, scale).expect("encode generated SRS");
            let second = encode_generated_srs(kind, scale).expect("repeat generated SRS");
            assert_eq!(first, second);
            assert_eq!(&first[..4], b"SRS\x02");

            let decoded = decode_srs(Cursor::new(&first)).expect("strictly decode generated SRS");
            assert_eq!(decoded.version(), SYNTHETIC_SRS_VERSION);
            assert_eq!(decoded.statistics(), generated_srs_statistics(kind, scale));
            let binary = decoded.compile().expect("compile decoded SRS");
            let synthetic = compile_generated_match_set(kind, scale).expect("compile synthetic");
            assert_eq!(binary.entry_counts().total(), scale);
            assert_eq!(synthetic.entry_counts().total(), scale);
            for case in match_probe_cases(kind, scale).expect("generated probes") {
                assert_eq!(probe_matches(&binary, &case.probe), case.expected);
                assert_eq!(probe_matches(&synthetic, &case.probe), case.expected);
            }
        }
    }

    #[test]
    fn generated_binary_srs_rows_are_paired_and_gated() {
        let _guard = allocator_test_lock();
        let mut measurements = Vec::new();
        let evidence = run_generated_binary_srs(&[10], 5, 1, &mut measurements)
            .expect("run generated binary SRS matrix");
        assert_eq!(evidence.len(), MatcherKind::ALL.len());
        assert_eq!(measurements.len(), 28);
        assert!(measurements.iter().all(|row| {
            row.suite == "match_set"
                && row.fixture.is_some()
                && row.compiled_entries == Some(10)
                && row.allocation_gate_applicable
                && row.allocation_gate_passed == Some(true)
                && row.timing_pair_id.is_some()
        }));
        let parity = collect_parity_observations(&measurements).expect("collect SRS parity");
        assert_eq!(parity.len(), 14);
        assert!(parity.iter().all(|row| {
            row.performance_gate_applicable
                && matches!(row.decision, "passed" | "failed")
                && row.baseline_id.contains("/synthetic_srs/")
                && row.candidate_id.contains("/binary_srs/")
        }));
    }

    #[test]
    fn paired_matchers_share_operation_counts_and_alternate_start_order() {
        let _guard = allocator_test_lock();
        let (ordinary, _) =
            build_generated_match_set(MatcherKind::Suffix, 100, false).expect("ordinary set");
        let (synthetic, _) =
            build_generated_match_set(MatcherKind::Suffix, 100, true).expect("synthetic set");
        let probe = MatchProbe::Domain(canonical("x.suffix-99.bench.invalid").expect("probe"));
        let (baseline, candidate) = benchmark_pair(
            ordinary.compiled(),
            synthetic.compiled(),
            &probe,
            5,
            1,
            "unit/paired-order".to_owned(),
        );
        assert_eq!(
            baseline.actual_iterations_per_sample,
            candidate.actual_iterations_per_sample
        );
        assert_eq!(baseline.paired_sample_order, candidate.paired_sample_order);
        let order = baseline.paired_sample_order.expect("paired order");
        assert!(order.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(
            baseline
                .sample_batch_nanoseconds
                .iter()
                .chain(&candidate.sample_batch_nanoseconds)
                .all(|elapsed| *elapsed >= MIN_SAMPLE_WINDOW_NANOSECONDS)
        );
    }

    #[test]
    fn route_mode_boundary_and_ruleset_evaluation_are_callable() {
        let _guard = allocator_test_lock();
        let small = build_route_fixture(64, RouteSource::RuleSet).expect("small route");
        let indexed = build_route_fixture(65, RouteSource::Mixed).expect("indexed route");
        assert_eq!(small.program.mode(), RuleProgramMode::SmallLinear);
        assert_eq!(indexed.program.mode(), RuleProgramMode::Indexed);

        let target = TargetAddr::domain("route-64.bench.invalid", 443).expect("target");
        let mut scratch = indexed.program.evaluation_scratch().expect("scratch");
        assert_eq!(
            evaluate_route(
                &indexed.program,
                indexed.snapshot.as_ref(),
                &target,
                64,
                &mut scratch,
            ),
            64
        );
        let measured = benchmark(
            || {
                evaluate_route(
                    &indexed.program,
                    indexed.snapshot.as_ref(),
                    &target,
                    64,
                    &mut scratch,
                ) as u64
            },
            5,
            32,
        );
        assert_eq!(measured.samples.len(), 5);
        assert_eq!(measured.allocation_samples.len(), 5);
        assert!(
            measured
                .allocation_samples
                .iter()
                .all(|sample| sample.iterations == 1)
        );
    }

    #[test]
    fn qualification_route_rows_cover_enabled_production_match_observation() {
        let _guard = allocator_test_lock();
        let mut rows = Vec::new();
        run_route_programs(&[64, 1_000], 5, 1, &mut rows).expect("route observation evidence");
        let observed = rows
            .iter()
            .filter(|row| row.source == "mixed_observed")
            .collect::<Vec<_>>();
        assert_eq!(observed.len(), 2);
        assert!(observed.iter().all(|row| {
            row.scale == 1_000
                && row.rule_program_mode == Some("indexed")
                && row.allocation_gate_passed == Some(true)
                && row.outcome_checksum != 0
        }));
        assert!(
            rows.iter()
                .filter(|row| row.scale == 64)
                .all(|row| row.source != "mixed_observed")
        );
    }

    #[test]
    fn dns_qname_sources_return_the_same_selected_rule() {
        let _guard = allocator_test_lock();
        let name = Name::from_str("dns-2.bench.invalid.").expect("name");
        for source in DnsQuerySource::ALL {
            let fixture = build_dns_qname_fixture(3, source).expect("DNS fixture");
            assert_eq!(evaluate_dns_qname(&fixture, &name), 2);
        }
    }

    #[test]
    fn dns_index_mode_and_candidate_evidence_cover_boundary_and_scale() {
        let _guard = allocator_test_lock();
        for (count, expected_mode) in [
            (64, RuleProgramMode::SmallLinear),
            (65, RuleProgramMode::Indexed),
            (1_000, RuleProgramMode::Indexed),
            (10_000, RuleProgramMode::Indexed),
        ] {
            let fixture = build_dns_qname_fixture(count, DnsQuerySource::Ordinary)
                .expect("DNS indexed evidence fixture");
            assert_eq!(fixture.program.mode(), expected_mode);
            let last = Name::from_str(&format!("dns-{}.bench.invalid.", count - 1))
                .expect("last DNS name");
            let (selected, visits) = evaluate_dns_qname_evidence(&fixture, &last);
            assert_eq!(selected, (count - 1) as u32);
            if expected_mode == RuleProgramMode::Indexed {
                assert!(visits < count, "{count} last-hit visits={visits}");
            }
            let miss =
                Name::from_str(&format!("dns-{count}.bench.invalid.")).expect("missing DNS name");
            let (_, visits) = evaluate_dns_qname_evidence(&fixture, &miss);
            if expected_mode == RuleProgramMode::Indexed {
                assert!(visits < count, "{count} miss visits={visits}");
            }
        }

        let mut rows = Vec::new();
        run_dns_qname(&[65], 5, 1, &mut rows).expect("DNS evidence rows");
        assert!(rows.iter().all(|row| {
            row.rule_program_mode == Some("indexed") && row.query_candidate_visits.is_some()
        }));
    }
}
