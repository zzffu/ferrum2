use ferrum2_rule::MatchSetCapabilities;
use ferrum2_rule::srs::SrsStatistics;
use serde::Serialize;

use crate::cli::Profile;

pub(crate) const REPORT_SCHEMA: &str = "ferrum2.rule-qualification.v3";

#[derive(Serialize)]
pub(crate) struct Report {
    pub(crate) schema: &'static str,
    pub(crate) generated_unix_millis: u128,
    pub(crate) profile: Profile,
    pub(crate) environment: EnvironmentFingerprint,
    pub(crate) repository: RepositoryFingerprint,
    pub(crate) runner: RunnerFingerprint,
    pub(crate) candidate: CandidateEvidence,
    pub(crate) configuration: RunConfiguration,
    pub(crate) measurement_policy: MeasurementPolicy,
    pub(crate) fixtures: Vec<FixtureEvidence>,
    pub(crate) measurements: Vec<Measurement>,
    pub(crate) parity_observations: Vec<ParityObservation>,
    pub(crate) snapshot_lifecycle: SnapshotLifecycleEvidence,
    pub(crate) scenario_count: usize,
    pub(crate) correctness_passed: bool,
    pub(crate) snapshot_lifecycle_passed: bool,
    pub(crate) allocation_gate_passed: bool,
    pub(crate) parity_gate_passed: bool,
    pub(crate) thresholds_passed: bool,
}

#[derive(Serialize)]
pub(crate) struct EnvironmentFingerprint {
    pub(crate) os: &'static str,
    pub(crate) architecture: &'static str,
    pub(crate) family: &'static str,
    pub(crate) logical_cpus: usize,
    pub(crate) cpu_model: Option<String>,
    pub(crate) rustc_version: Option<String>,
    pub(crate) timer: &'static str,
    pub(crate) build_profile: &'static str,
}

#[derive(Serialize)]
pub(crate) struct RepositoryFingerprint {
    pub(crate) git_head: Option<String>,
    pub(crate) git_tree: Option<String>,
    pub(crate) tree_state: &'static str,
    pub(crate) changed_entries: Option<usize>,
    pub(crate) status_sha256: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct RunnerFingerprint {
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CandidateEvidence {
    pub(crate) adoption_claim: bool,
    pub(crate) enabled_features: Vec<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct RunConfiguration {
    pub(crate) match_sizes: Vec<usize>,
    pub(crate) route_sizes: Vec<usize>,
    pub(crate) dns_rule_sizes: Vec<usize>,
    pub(crate) snapshot_reader_threads: usize,
    pub(crate) samples: usize,
    pub(crate) base_iterations_per_sample: u64,
    pub(crate) includes_100k: bool,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SnapshotLifecycleEvidence {
    pub(crate) reader_threads: usize,
    pub(crate) initial_generation: u64,
    pub(crate) published_generation: u64,
    pub(crate) reader_generation: u64,
    pub(crate) reader_action: u8,
    pub(crate) fresh_generation: u64,
    pub(crate) fresh_action: u8,
    pub(crate) returned_old_generation: u64,
    pub(crate) returned_old_matches_initial: bool,
    pub(crate) old_snapshot_alive_before_reader_release: bool,
    pub(crate) old_snapshot_released_after_reader_release: bool,
    pub(crate) generation_action_consistent: bool,
    pub(crate) publish_monotonic: bool,
    pub(crate) watch_observed_generation: u64,
    pub(crate) watch_no_missed_publication: bool,
}

#[derive(Serialize)]
pub(crate) struct MeasurementPolicy {
    pub(crate) latency_source: &'static str,
    pub(crate) minimum_reported_batch_nanoseconds: u64,
    pub(crate) calibration: &'static str,
    pub(crate) warmup_batches: usize,
    pub(crate) paired_order: &'static str,
    pub(crate) retained_samples: bool,
    pub(crate) allocation_measurement: &'static str,
    pub(crate) compiled_memory_measurement: &'static str,
    pub(crate) local_parity_target_percent: f64,
    pub(crate) noisy_gate_ceiling_percent: f64,
    pub(crate) p99_parity_target_percent: f64,
    pub(crate) thresholds_enforced_by_runner: bool,
    pub(crate) parity_gate_scope: &'static str,
    pub(crate) paired_observation_scope: &'static str,
    pub(crate) allocation_gate_scope: &'static str,
    pub(crate) note: &'static str,
}

#[derive(Serialize)]
pub(crate) struct FixtureEvidence {
    pub(crate) name: String,
    pub(crate) provenance: &'static str,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) srs_version: u8,
    pub(crate) statistics: SerializableSrsStatistics,
    pub(crate) capabilities: SerializableCapabilities,
}

#[derive(Serialize)]
pub(crate) struct SerializableSrsStatistics {
    pub(crate) rules: u64,
    pub(crate) exact_domains: usize,
    pub(crate) domain_suffixes: usize,
    pub(crate) domain_keywords: usize,
    pub(crate) ip_cidrs: usize,
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
pub(crate) struct SerializableCapabilities {
    pub(crate) exact_domain: bool,
    pub(crate) domain_suffix: bool,
    pub(crate) domain_keyword: bool,
    pub(crate) ip_cidr: bool,
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
pub(crate) struct Measurement {
    pub(crate) id: String,
    pub(crate) suite: &'static str,
    pub(crate) source: String,
    pub(crate) scenario: String,
    pub(crate) scale: usize,
    pub(crate) fixture: Option<String>,
    pub(crate) rule_program_mode: Option<&'static str>,
    pub(crate) query_candidate_visits: Option<usize>,
    pub(crate) requested_min_iterations_per_sample: u64,
    pub(crate) actual_iterations_per_sample: Vec<u64>,
    pub(crate) sample_batch_nanoseconds: Vec<u64>,
    pub(crate) timing_pair_id: Option<String>,
    pub(crate) paired_sample_order: Option<Vec<&'static str>>,
    pub(crate) samples_ns_per_op: Vec<f64>,
    pub(crate) p50_ns_per_op: f64,
    pub(crate) p99_ns_per_op: f64,
    pub(crate) queries_per_second_from_p50: Option<f64>,
    pub(crate) build_nanoseconds: u128,
    pub(crate) compiled_allocations: u64,
    pub(crate) compiled_reallocations: u64,
    pub(crate) compiled_entries: Option<usize>,
    pub(crate) compiled_bytes_per_entry: Option<f64>,
    pub(crate) allocation_samples: Vec<AllocationSample>,
    pub(crate) allocations_per_op: f64,
    pub(crate) reallocations_per_op: f64,
    pub(crate) bytes_allocated_per_op: f64,
    pub(crate) bytes_deallocated_per_op: f64,
    pub(crate) compiled_memory_bytes: u64,
    pub(crate) allocation_status: &'static str,
    pub(crate) compiled_memory_status: &'static str,
    pub(crate) allocation_gate_applicable: bool,
    pub(crate) allocation_gate_passed: Option<bool>,
    pub(crate) correctness: &'static str,
    pub(crate) outcome_checksum: u64,
}

#[derive(Serialize)]
pub(crate) struct ParityObservation {
    pub(crate) suite: &'static str,
    pub(crate) scenario: String,
    pub(crate) scale: usize,
    pub(crate) baseline_id: String,
    pub(crate) candidate_id: String,
    pub(crate) median_delta_percent: Option<f64>,
    pub(crate) p99_delta_percent: Option<f64>,
    pub(crate) median_limit_percent: f64,
    pub(crate) p99_limit_percent: f64,
    pub(crate) performance_gate_applicable: bool,
    pub(crate) decision: &'static str,
}

pub(crate) struct BenchResult {
    pub(crate) samples: Vec<f64>,
    pub(crate) actual_iterations_per_sample: Vec<u64>,
    pub(crate) sample_batch_nanoseconds: Vec<u64>,
    pub(crate) timing_pair_id: Option<String>,
    pub(crate) paired_sample_order: Option<Vec<&'static str>>,
    pub(crate) p50: f64,
    pub(crate) p99: f64,
    pub(crate) checksum: u64,
    pub(crate) allocation_samples: Vec<AllocationSample>,
    pub(crate) allocations_per_op: f64,
    pub(crate) reallocations_per_op: f64,
    pub(crate) bytes_allocated_per_op: f64,
    pub(crate) bytes_deallocated_per_op: f64,
    pub(crate) allocation_free: bool,
}

pub(crate) struct AllocationEvidence {
    pub(crate) samples: Vec<AllocationSample>,
    pub(crate) allocations_per_op: f64,
    pub(crate) reallocations_per_op: f64,
    pub(crate) bytes_allocated_per_op: f64,
    pub(crate) bytes_deallocated_per_op: f64,
    pub(crate) allocation_free: bool,
    pub(crate) checksum: u64,
}

#[derive(Serialize)]
pub(crate) struct AllocationSample {
    pub(crate) iterations: u64,
    pub(crate) allocations: u64,
    pub(crate) deallocations: u64,
    pub(crate) reallocations: u64,
    pub(crate) bytes_allocated: u64,
    pub(crate) bytes_deallocated: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct BuildEvidence {
    pub(crate) nanoseconds: u128,
    pub(crate) allocations: u64,
    pub(crate) reallocations: u64,
    pub(crate) net_retained_bytes: u64,
}

impl BuildEvidence {
    pub(crate) fn combined(self, other: Self) -> Self {
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
