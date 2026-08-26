use std::collections::{BTreeMap, BTreeSet};

use ferrum2_rule::RuleProgramMode;

use crate::cli::{QualificationError, Result};
use crate::report::{BenchResult, BuildEvidence, Measurement, ParityObservation};

pub(crate) const LOCAL_PARITY_TARGET_PERCENT: f64 = 5.0;
pub(crate) const NOISY_GATE_CEILING_PERCENT: f64 = 10.0;
pub(crate) const P99_PARITY_TARGET_PERCENT: f64 = 15.0;

pub(crate) fn nearest_rank(values: &[f64], percentile: usize) -> f64 {
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let rank = (percentile * ordered.len()).div_ceil(100);
    ordered[rank.saturating_sub(1)]
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn measurement(
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

pub(crate) fn ensure_unique_measurement_ids(measurements: &[Measurement]) -> Result<()> {
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

pub(crate) fn collect_parity_observations(
    measurements: &[Measurement],
) -> Result<Vec<ParityObservation>> {
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

pub(crate) fn within_limit(delta: Option<f64>, limit: f64) -> bool {
    delta.is_some_and(|value| value.abs() <= limit)
}

pub(crate) fn percent_delta(baseline: f64, candidate: f64) -> Option<f64> {
    if baseline == 0.0 {
        return None;
    }
    Some((candidate - baseline) * 100.0 / baseline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurement::allocation::allocator_test_lock;

    #[test]
    fn nearest_rank_retains_observed_values() {
        let _guard = allocator_test_lock();
        let values = [8.0, 2.0, 5.0, 1.0, 9.0];
        assert_eq!(nearest_rank(&values, 50), 5.0);
        assert_eq!(nearest_rank(&values, 99), 9.0);
    }
}
