//! DNS process observations explicitly separate from unobserved query-owner drain.

use super::evidence_support::DnsLoadReport;
use serde_json::{Value, json};

pub(super) const REQUIRED_EQUAL_INTERVALS: usize = 3;

#[derive(Default)]
pub(super) struct ProcessTupleStability {
    previous: Option<(u64, u64, u64, u64)>,
    equal_intervals: usize,
}

impl ProcessTupleStability {
    pub(super) fn observe(&mut self, tuple: (u64, u64, u64, u64)) -> bool {
        if self.previous == Some(tuple) {
            self.equal_intervals = (self.equal_intervals + 1).min(REQUIRED_EQUAL_INTERVALS);
        } else {
            self.previous = Some(tuple);
            self.equal_intervals = 0;
        }
        self.equal_intervals == REQUIRED_EQUAL_INTERVALS
    }
}

fn unverified_query_drain() -> Value {
    json!({"status": "UNVERIFIED", "reason": "query-owner-observation-unavailable"})
}

pub(super) fn phase_completion(phase: &str, load: &DnsLoadReport) -> Value {
    json!({
        "kind": "dns_resource_phase_completion", "phase": phase,
        "completed_queries": load.verified, "process_bounds": "PASS",
        "load_work": {"sent": load.sent, "verified": load.verified, "unfinished": load.unfinished},
        "post_load_stability": "PASS", "equal_intervals": REQUIRED_EQUAL_INTERVALS,
        "query_drain": unverified_query_drain(),
    })
}

pub(super) fn complete_observation(
    direct_queries: usize,
    detoured_queries: usize,
    cleanup: impl FnOnce() -> Result<(), String>,
) -> Result<Value, String> {
    cleanup()?;
    Ok(json!({
        "schema_version": 2, "kind": "dns_resource_summary", "roots": "client,server",
        "phases": "idle,direct,detoured", "direct_queries": direct_queries,
        "detoured_queries": detoured_queries,
        "samples": super::dns_resource::DNS_RESOURCE_SAMPLES * 2, "rss_windows": 12,
        "process_bounds": "PASS", "post_load_stability": "PASS", "process_shutdown": "PASS",
        "harness_join": "PASS", "rebind": "PASS", "query_drain": unverified_query_drain(),
        "production_recovery_qualified": false, "status": "OBSERVATION_COMPLETE",
    }))
}

#[cfg(test)]
mod dns_contract_tests {
    use super::*;

    #[test]
    fn stable_process_counts_never_become_query_recovery_evidence() {
        let mut stability = ProcessTupleStability::default();
        assert!(!stability.observe((10, 11, 12, 13)));
        assert!(!stability.observe((10, 11, 12, 13)));
        assert!(!stability.observe((11, 11, 12, 13)));
        assert!(!stability.observe((11, 11, 12, 13)));
        assert!(!stability.observe((11, 11, 12, 13)));
        assert!(stability.observe((11, 11, 12, 13)));
        assert_eq!(
            phase_completion(
                "direct",
                &DnsLoadReport {
                    sent: 42,
                    verified: 42,
                    unfinished: 0
                }
            ),
            json!({
                "kind": "dns_resource_phase_completion", "phase": "direct", "completed_queries": 42,
                "process_bounds": "PASS", "post_load_stability": "PASS", "equal_intervals": 3,
                "load_work": {"sent": 42, "verified": 42, "unfinished": 0},
                "query_drain": {"status": "UNVERIFIED", "reason": "query-owner-observation-unavailable"},
            })
        );
    }

    #[test]
    fn final_observation_requires_cleanup_and_remains_unqualified() {
        assert_eq!(
            complete_observation(42, 43, || Err("join failed".to_owned())),
            Err("join failed".to_owned())
        );
        assert_eq!(
            complete_observation(42, 43, || Ok(())).unwrap(),
            json!({
                "schema_version": 2, "kind": "dns_resource_summary", "roots": "client,server",
                "phases": "idle,direct,detoured", "direct_queries": 42, "detoured_queries": 43,
                "samples": 48, "rss_windows": 12, "process_bounds": "PASS", "post_load_stability": "PASS",
                "process_shutdown": "PASS", "harness_join": "PASS", "rebind": "PASS",
                "query_drain": {"status": "UNVERIFIED", "reason": "query-owner-observation-unavailable"},
                "production_recovery_qualified": false, "status": "OBSERVATION_COMPLETE",
            })
        );
    }
}
